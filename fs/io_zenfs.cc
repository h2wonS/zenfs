// Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved.
// Copyright (c) 2019-present, Western Digital Corporation
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#if !defined(ROCKSDB_LITE) && !defined(OS_WIN)

#include "io_zenfs.h"
#include "zbd_zenfs.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libzbd/zbd.h>
#include <linux/blkzoned.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <string>
#include <utility>
#include <vector>

#include "rocksdb/env.h"
#include "util/coding.h"

#define NThread false
extern int start_level;
extern int base_fnum;
extern bool is_for_compaction;
extern bool isDataBlock;

namespace ROCKSDB_NAMESPACE {

extern std::shared_ptr<Logger> _logger;


ZoneExtent::ZoneExtent(uint64_t start, uint32_t length, Zone* zone,
                       char* key_smallest, char* key_largest, bool isValidkey, int id)
    : start_(start), length_(length), zone_(zone),
    key_smallest_(key_smallest),
    key_largest_(key_largest),
    isValidkey_(isValidkey),
    id_(id) {}

Status ZoneExtent::DecodeFrom(Slice* input) {
  if (input->size() != (sizeof(start_) + sizeof(length_)))
    return Status::Corruption("ZoneExtent", "Error: length missmatch");

  GetFixed64(input, &start_);
  GetFixed32(input, &length_);
  return Status::OK();
}

void ZoneExtent::EncodeTo(std::string* output) {
  PutFixed64(output, start_);
  PutFixed32(output, length_);
}

void ZoneExtent::EncodeJson(std::ostream& json_stream) {
  json_stream << "{";
  json_stream << "\"start\":" << start_ << ",";
  json_stream << "\"length\":" << length_;
  json_stream << "}";
}

enum ZoneFileTag : uint32_t {
  kFileID = 1,
  kFileName = 2,
  kFileSize = 3,
  kWriteLifeTimeHint = 4,
  kExtent = 5,
  kModificationTime = 6,
};

void ZoneFile::EncodeTo(std::string* output, uint32_t extent_start) {
  PutFixed32(output, kFileID);
  PutFixed64(output, file_id_);

  PutFixed32(output, kFileName);
  PutLengthPrefixedSlice(output, Slice(filename_));

  PutFixed32(output, kFileSize);
  PutFixed64(output, fileSize);

  PutFixed32(output, kWriteLifeTimeHint);
  PutFixed32(output, (uint32_t)lifetime_);

  for (uint32_t i = extent_start; i < extents_.size(); i++) {
    std::string extent_str;

    PutFixed32(output, kExtent);
    extents_[i]->EncodeTo(&extent_str);
    PutLengthPrefixedSlice(output, Slice(extent_str));
  }

  PutFixed32(output, kModificationTime);
  PutFixed64(output, (uint64_t)m_time_);
  /* We're not encoding active zone and extent start
   * as files will always be read-only after mount */
}

void ZoneFile::EncodeJson(std::ostream& json_stream) {
  json_stream << "{";
  json_stream << "\"id\":" << file_id_ << ",";
  json_stream << "\"filename\":\"" << filename_ << "\",";
  json_stream << "\"size\":" << fileSize << ",";
  json_stream << "\"hint\":" << lifetime_ << ",";
  json_stream << "\"extents\":[";

  bool first_element = true;
  for (ZoneExtent* extent : extents_) {
    if (first_element) {
      first_element = false;
    } else {
      json_stream << ",";
    }
    extent->EncodeJson(json_stream);
  }
  json_stream << "]}";
}

Status ZoneFile::DecodeFrom(Slice* input) {
  uint32_t tag = 0;

  GetFixed32(input, &tag);
  if (tag != kFileID || !GetFixed64(input, &file_id_))
    return Status::Corruption("ZoneFile", "File ID missing");

  while (true) {
    Slice slice;
    ZoneExtent* extent;
    Status s;

    if (!GetFixed32(input, &tag)) break;

    switch (tag) {
      case kFileName:
        if (!GetLengthPrefixedSlice(input, &slice))
          return Status::Corruption("ZoneFile", "Filename missing");
        filename_ = slice.ToString();
        if (filename_.length() == 0)
          return Status::Corruption("ZoneFile", "Zero length filename");
        break;
      case kFileSize:
        if (!GetFixed64(input, &fileSize))
          return Status::Corruption("ZoneFile", "Missing file size");
        break;
      case kWriteLifeTimeHint:
        uint32_t lt;
        if (!GetFixed32(input, &lt))
          return Status::Corruption("ZoneFile", "Missing life time hint");
        lifetime_ = (Env::WriteLifeTimeHint)lt;
        break;
      case kExtent:
        extent = new ZoneExtent(0, 0, nullptr, nullptr, nullptr, false, -1);
        GetLengthPrefixedSlice(input, &slice);
        s = extent->DecodeFrom(&slice);
        if (!s.ok()) {
          delete extent;
          return s;
        }
        extent->zone_ = zbd_->GetIOZone(extent->start_);
        if (!extent->zone_)
          return Status::Corruption("ZoneFile", "Invalid zone extent");
        extent->zone_->used_capacity_ += extent->length_;
        extents_.push_back(extent);
        break;
      case kModificationTime:
        uint64_t ct;
        if (!GetFixed64(input, &ct))
          return Status::Corruption("ZoneFile", "Missing creation time");
        m_time_ = (time_t)ct;
        break;
      default:
        return Status::Corruption("ZoneFile", "Unexpected tag");
    }
  }

  MetadataSynced();
  return Status::OK();
}

Status ZoneFile::MergeUpdate(std::shared_ptr<ZoneFile> update) {
  if (file_id_ != update->GetID())
    return Status::Corruption("ZoneFile update", "ID missmatch");

  Rename(update->GetFilename());
  SetFileSize(update->GetFileSize());
  SetWriteLifeTimeHint(update->GetWriteLifeTimeHint());
  SetFileModificationTime(update->GetFileModificationTime());

  std::vector<ZoneExtent*> update_extents = update->GetExtents();
  for (long unsigned int i = 0; i < update_extents.size(); i++) {
    ZoneExtent* extent = update_extents[i];
    Zone* zone = extent->zone_;
    zone->used_capacity_ += extent->length_;
    extents_.push_back(new ZoneExtent(extent->start_, extent->length_, zone, nullptr, nullptr, true, -1));
  }

  MetadataSynced();

  return Status::OK();
}

ZoneFile::ZoneFile(ZonedBlockDevice* zbd, std::string filename,
                   uint64_t file_id)
    : zbd_(zbd),
      active_zone_(NULL),
      extent_start_(0),
      extent_filepos_(0),
      lifetime_(Env::WLTH_NOT_SET),
      fileSize(0),
      filename_(filename),
      file_id_(file_id),
      nr_synced_extents_(0),
      m_time_(0) {
  IOStatus s = IOStatus::OK();

  s = zbd->StaticAllocateZones(&static_zone_vec);     
  if(!s.ok()) assert(false);
  else{
//    Info(zbd_->logger_,"allocate zone vector filename = %s\n", filename_.c_str());
//    for(int i=0;i<22;i++) Info(zbd_->logger_,"zone = %d used_cap = %ld\n", static_zone_vec[i]->GetZoneNr(), static_zone_vec[i]->used_capacity_.load(std::memory_order_relaxed)/(long)1024/(long)1024);
  }
  for(int i=0;i<22;i++) zone_vec_lock[i]=0;
  position=0;
      }

std::string ZoneFile::GetFilename() { return filename_; }
void ZoneFile::Rename(std::string name) { filename_ = name; }
time_t ZoneFile::GetFileModificationTime() { return m_time_; }

uint64_t ZoneFile::GetFileSize() { return fileSize; }
void ZoneFile::SetFileSize(uint64_t sz) { fileSize = sz; }
void ZoneFile::SetFileModificationTime(time_t mt) { m_time_ = mt; }

ZoneFile::~ZoneFile() {
  for (auto e = std::begin(extents_); e != std::end(extents_); ++e) {
    if( (*e)->isValidkey_ != false) continue;
    Zone* zone = (*e)->zone_;
    assert(zone && zone->used_capacity_ >= (*e)->length_);
    zone->used_capacity_ -= (*e)->length_;
    delete *e;
//    zone->Reset(); 
  }
  static_zone_vec.clear();
  IOStatus s = CloseWR();
  if (!s.ok()) {
    zbd_->SetZoneDeferredStatus(s);
  }

}

IOStatus ZoneFile::CloseWR() {
  IOStatus s = IOStatus::OK();

  s = CloseActiveZone();
  open_for_wr_ = false;

  return s;
}

IOStatus ZoneFile::CloseActiveZone() {
  IOStatus s = IOStatus::OK();
  if (active_zone_) {
    s = active_zone_->CloseWR();
    if (!s.ok()) {
      return s;
    }
    ReleaseActiveZone();
    zbd_->NotifyIOZoneClosed();
  }
  return s;
}

void ZoneFile::OpenWR() { open_for_wr_ = true; }

bool ZoneFile::IsOpenForWR() { return open_for_wr_; }

ZoneExtent* ZoneFile::GetExtent(uint64_t file_offset, uint64_t* dev_offset) {
  for (unsigned int i = 0; i < extents_.size(); i++) {
   if (file_offset < extents_[i]->length_) {
      *dev_offset = extents_[i]->start_ + file_offset;  
      printf("%s GetExtent:: fileoffset=%lu, file_offset=0x%lx, extent_id=%d, extent_start = 0x%lx, length = %u r_off(devoff)=0x%lx\n"
        , getFilename().c_str(), file_offset, file_offset, extents_[i]->id_, extents_[i]->start_, extents_[i]->length_, extents_[i]->start_+file_offset);
      return extents_[i];
    } else {
      file_offset -= extents_[i]->length_;
    }
  }
  return NULL;
}

static int invalidread_extent = -1;

IOStatus ZoneFile::PositionedRead(uint64_t offset, size_t n, Slice* result,
                                  char* scratch, bool direct,
                                  char* smallest, char* largest, int s_len, int l_len) {
  ZenFSMetricsLatencyGuard guard(zbd_->GetMetrics(), ZENFS_READ_LATENCY,
                                 Env::Default());
  zbd_->GetMetrics()->ReportQPS(ZENFS_READ_QPS, 1);

  int f = zbd_->GetReadFD();
  int f_direct = zbd_->GetReadDirectFD();
  char* ptr;
  uint64_t r_off;
  size_t r_sz;
  ssize_t r = 0;
  size_t read = 0;
  ZoneExtent* extent;
  uint64_t extent_end;
  IOStatus s;

  if (offset >= fileSize) {
    printf("%s PositionedRead offset is larger than fileSize,  fileSize=%ld, offset=%lu, toreadSize=%ld\n", getFilename().c_str(), GetFileSize(), offset, n);
    *result = Slice(scratch, 0);
    return IOStatus::OK();
  }

  r_off = 0;
  extent = GetExtent(offset, &r_off);
  if (!extent) {
    /* read start beyond end of (synced) file data*/
    *result = Slice(scratch, 0);
    return s;
  }
if (is_for_compaction && start_level && smallest!=nullptr && getFilename().substr(getFilename().size() - 3) == "sst") {
  //printf("Try Read ZoneNR=%ld Filename=%s l_len=%d\n", extent->zone_->GetZoneNr(), getFilename().c_str(), l_len);
  Slice c_smallest = Slice(extent->key_smallest_, l_len);
  Slice r_largest = Slice(largest, l_len);
  if(c_smallest.compare(r_largest) > 0){
    printf("%s [Read] ChunkSmallest is larger than ReadLargest!!  ZoneNR=%ld\n", getFilename().c_str(), extent->zone_->GetZoneNr());
    if(isDataBlock){
    printf("Chunk_smallest=(l_len=%d)", l_len);
    for(int i=0; i<l_len; i++){
      printf("%x", c_smallest.data()[i]);
    }
    printf("    ");
    printf("Read_largest=(l_len=%d)", l_len);
    for(int i=0; i<l_len; i++){
      printf("%x", r_largest.data()[i]);
    }
    printf("\nCompare:: %d\n", c_smallest.compare(r_largest));
    printf("file offset=0x%lx FileSize=%ld ", offset, fileSize);
    printf("extent->start offset=0x%lx extent->id=%d\n", extent->start_, extent->id_);
  }
  }else {
    extent->isValidkey_ = false;
   printf("[READ] Normal PosRead:: file offset=0x%lx toread=%ld FileSize=%ld ", offset, n, fileSize);
    printf("extent->start offset=0x%lx extent->id=%d\n", extent->start_, extent->id_);
 
  }
}
  extent_end = extent->start_ + extent->length_;

  /* Limit read size to end of file */
  if ((offset + n) > fileSize)
    r_sz = fileSize - offset;
  else
    r_sz = n;

  ptr = scratch;

  while (read != r_sz && invalidread_extent != extent->id_) {
    size_t pread_sz = r_sz - read;
      printf("PosRead:: pread_sz=%ld r_sz(tot)=%ld, read=%ld\n", pread_sz, r_sz, read);

    if ((pread_sz + r_off) > extent_end){
       pread_sz = extent_end - r_off;
      printf("PosRead:: read until extent_end:: pread_sz=%ld r_off=0x%lx, extent_end=0x%lx\n", pread_sz, r_off, extent_end);
    }

    /* We may get some unaligned direct reads due to non-aligned extent lengths,
     * so fall back on non-direct-io in that case.
     */

    bool aligned = (pread_sz % zbd_->GetBlockSize() == 0);
    printf("PosRead:: bool aligned=%d pread_sz=%ld\n", aligned, pread_sz);
    if (direct && aligned) {
      r = pread(f_direct, ptr, pread_sz, r_off);
      printf("Direct read PREADSZ=%ld\n", pread_sz);
      if(r == -1) printf("direct read error in io_zenfs.cc\n");
    } else {
      r = pread(f, ptr, pread_sz, r_off);
      printf("Undirect read or not aligned PREADSZ=%ld\n", pread_sz);
      if(r == -1) printf("read error in io_zenfs.cc\n");
    }

    if (r <= 0) {
      if (r == -1 && errno == EINTR) {
        continue;
      }
      break;
    }

    pread_sz = (size_t)r;

    ptr += pread_sz;
    read += pread_sz;
    r_off += pread_sz;

    if (read != r_sz && r_off == extent_end) {
      extent = GetExtent(offset + read, &r_off);
      if (is_for_compaction && start_level && smallest!=nullptr && getFilename().substr(getFilename().size() - 3) == "sst") {
        //printf("Try2 Read ZoneNR=%ld Filename=%s l_len=%d\n", extent->zone_->GetZoneNr(), getFilename().c_str(), l_len);
        Slice c_smallest = Slice(extent->key_smallest_, l_len);
        Slice r_largest = Slice(largest, l_len);
        if(isDataBlock){
          if(c_smallest.compare(r_largest) > 0){
            printf("Next Chunk_smallest=");
            for(int i=0; i<l_len; i++){
              printf("%x", c_smallest.data()[i]);
            }
            printf("    ");
            printf("Read_largest=");
            for(int i=0; i<l_len; i++){
              printf("%x", r_largest.data()[i]);
            }
            printf("\nCompare:: %d\n", c_smallest.compare(r_largest));
            printf("file offset=0x%lx FileSize=%ld, %ld(MB)  ", offset+read, fileSize, fileSize/1024/1024);
            printf("extent->start offset=0x%lx, extent->id=%d\n", extent->start_, extent->id_);
            printf("Left Read Size =%ld, %ld(kB)\n", read, read/1024);
            //read = r_sz;
            //printf("[READ] Modified Read Size =%d, %d(kB)\n", read, read/1024);
            invalidread_extent = extent->id_;
            printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
            break;
          }
        }else {
          extent->isValidkey_ = false;
        }
      }
      if (!extent) {
        /* read beyond end of (synced) file data */
        break;
      }
      r_off = extent->start_;
      extent_end = extent->start_ + extent->length_;
      assert(((size_t)r_off % zbd_->GetBlockSize()) == 0);
    }
  }

  if (r < 0) {
    s = IOStatus::IOError("pread error\n");
    read = 0;
  }

  if (read == 0 && invalidread_extent != extent->id_) {
    printf("ABORTED::%s, r=%ld, read=%ld, extent->id_=%d, extent->start_off=0x%lx,r_sz=%ld, offset=0x%lx, sizeread_n = %ld, fileSize=%ld ZoneNR=%ld extent->len=%d\n",
    getFilename().c_str(), r, read, extent->id_, extent->start_, r_sz, offset, n, fileSize,
    extent->zone_->GetZoneNr(), extent->length_);   
      abort();
  }
  *result = Slice((char*)scratch, read);
  if(isDataBlock && is_for_compaction && start_level){
    printf("End of PositionedRead :: result size=%ld\n", result->size());
  }
  return s;
}

IOStatus ZoneFile::PositionedRead(uint64_t offset, size_t n, Slice* result,
                                  char* scratch, bool direct) {

  ZenFSMetricsLatencyGuard guard(zbd_->GetMetrics(), ZENFS_READ_LATENCY,
                                 Env::Default());
  zbd_->GetMetrics()->ReportQPS(ZENFS_READ_QPS, 1);

  int f = zbd_->GetReadFD();
  int f_direct = zbd_->GetReadDirectFD();
  char* ptr;
  uint64_t r_off;
  size_t r_sz;
  ssize_t r = 0;
  size_t read = 0;
  ZoneExtent* extent;
  uint64_t extent_end;
  IOStatus s;

  if (offset >= fileSize) {
    *result = Slice(scratch, 0);
    return IOStatus::OK();
  }

  r_off = 0;
  extent = GetExtent(offset, &r_off);
  if (!extent) {
    /* read start beyond end of (synced) file data*/
    *result = Slice(scratch, 0);
    return s;
  }
  extent_end = extent->start_ + extent->length_;

  /* Limit read size to end of file */
  if ((offset + n) > fileSize)
    r_sz = fileSize - offset;
  else
    r_sz = n;

  ptr = scratch;

  while (read != r_sz) {
    size_t pread_sz = r_sz - read;

    if ((pread_sz + r_off) > extent_end) pread_sz = extent_end - r_off;

    /* We may get some unaligned direct reads due to non-aligned extent lengths,
     * so fall back on non-direct-io in that case.
     */
    bool aligned = (pread_sz % zbd_->GetBlockSize() == 0);
    if (direct && aligned) {
      r = pread(f_direct, ptr, pread_sz, r_off);
      if(r == -1) printf("direct read error in io_zenfs.cc\n");
    } else {
      r = pread(f, ptr, pread_sz, r_off);
      if(r == -1) printf("read error in io_zenfs.cc\n");
    }

    if (r <= 0) {
      if (r == -1 && errno == EINTR) {
        continue;
      }
      break;
    }

    pread_sz = (size_t)r;

    ptr += pread_sz;
    read += pread_sz;
    r_off += pread_sz;

    if (read != r_sz && r_off == extent_end) {
      extent = GetExtent(offset + read, &r_off);
      if (!extent) {
        /* read beyond end of (synced) file data */
        break;
      }
      r_off = extent->start_;
      extent_end = extent->start_ + extent->length_;
      assert(((size_t)r_off % zbd_->GetBlockSize()) == 0);
    }
  }

  if (r < 0) {
    s = IOStatus::IOError("pread error\n");
    read = 0;
  }

  if (read == 0) {
      abort();
  }
  *result = Slice((char*)scratch, read);
  return s;
}

void ZoneFile::PushExtent2(size_t wr_size, char* smallest, char* largest, int s_len, int l_len) {
  //printf("PushExtent:: filename = %s, extent_start = 0x%lx, length = %u\n"
  //      , getFilename().c_str(), active_zone_->start_, wr_size);

  ZoneExtent* extent = new ZoneExtent(active_zone_->wp_, wr_size, active_zone_, nullptr, nullptr, false, -1);
  extents_.push_back(extent);
 active_zone_->used_capacity_ += wr_size;
  extent_filepos_ = fileSize;
}

void ZoneFile::PushExtent() {
  uint64_t length;

  if (fileSize < extent_filepos_) {
    // When trucating this file, filesize may decrease.
    extent_filepos_ = fileSize;
  }

  if (getFilename().substr(getFilename().size() - 3) == "sst") {
    return;
  }

  if (!active_zone_) return;

  assert(fileSize >= extent_filepos_);

  length = fileSize - extent_filepos_;
  if (length == 0) return;
  assert(length <= (active_zone_->wp_ - extent_start_));
  extents_.push_back(new ZoneExtent(extent_start_, length, active_zone_, nullptr, nullptr, false, -1));

  active_zone_->used_capacity_ += length;
  extent_start_ = active_zone_->wp_;
  extent_filepos_ = fileSize;
}

static void thread_append(Zone *zone, char *data, uint32_t size, IODebugContext* dbg){
  
  Info(_logger, "zone %d thread_append start\n", zone->GetZoneNr());
  IOStatus s = zone->Append(data, size);
  if(!s.ok()) {
    printf("write error\n");
    assert(false);
  }
  Info(_logger, "zone %d thread_append end\n", zone->GetZoneNr());
  zone->zone_lock = 0;
//  zone->Finish();
//  dbg->buf_->RefitTail(dbg->file_advance_, dbg->leftover_tail_);
//  delete dbg->buf_->Release();
}

/* Assumes that data and size are block aligned */
IOStatus ZoneFile::Append(void* data, int data_size, int valid_size, IODebugContext* dbg,
                          char* smallest, char* largest, int s_len, int l_len) {
  printf("%s ZoneFile::Append data_size=%d\n", getFilename().c_str(), data_size);
  uint32_t left = data_size;
  uint32_t wr_size, offset = 0;
  uint32_t tmp_cap;
  IOStatus s = IOStatus::OK();

  if(data_size != valid_size){
    printf("diff data_size and valid_size\n");
  }
  
  Zone* zone = nullptr;
//Allocate zone from vector
  int get_zone = 0;
  
  while(!get_zone){
    bool left_zone = false;
    auto& atom = static_zone_vec[position]; 
    if(atom->zone_lock == 0 && atom->capacity_ >= 3*192*1024){ 
      zone = atom;
      atom->zone_lock = 1;
      get_zone = 1;
      position = position+1;
      if(position == static_zone_vec.size()) position = 0;
//        Info(zbd_->logger_, "lock get zone file = %s zone %d\n", filename_.c_str(), zone->GetZoneNr());
      break;
    }
  }

  if (!zone) {
    return IOStatus::NoSpace(
        "Out of space: Zone allocation failure while setting active zone");
  }

  SetActiveZone(zone);
  extent_start_ = active_zone_->wp_;
  extent_filepos_ = fileSize; 

  wr_size = left;
  if (wr_size > active_zone_->capacity_) wr_size = active_zone_->capacity_;

  PushExtent2(wr_size, smallest, largest, s_len, l_len);
  extents_.back()->key_smallest_ = new char[s_len+1];
  extents_.back()->key_largest_ = new char[l_len+1];
  for(int i=0; i<s_len; i++){
    extents_.back()->key_smallest_[i] = smallest[i];
  }
  for(int i=0; i<l_len; i++){
    extents_.back()->key_largest_[i] = largest[i];
  }
  extents_.back()->isValidkey_ = true;
  extents_.back()->id_ = static_cast<int>(extents_.size());
  if (true) {
  printf("%s [WRITE] ZoneNr=%d, filesize=%ld  ", getFilename().c_str(), active_zone_->GetZoneNr(), fileSize);
    printf("Push EXTENT INFO###################\nSmallestKey=");
    for (int i=0; i<s_len; i++){
      printf("%x", extents_.back()->key_smallest_[i]);
    }
    printf("  ");
    printf("LargestKey=");
    for (int i=0; i<l_len; i++){
      printf("%x", extents_.back()->key_largest_[i]);
    }
    printf("\n");
  printf("extent_start = 0x%lx extent_id=%d wr_size(length)=%d offset=0x%x\n#########################\n", 
  active_zone_->wp_, extents_.back()->id_, wr_size, offset+wr_size);
}
 
  //  Info(zbd_->logger_, "add write thread filename = %s zone %d", filename_.c_str(), active_zone_->GetZoneNr());
  
  thread_pool_.push_back(std::thread(thread_append, active_zone_, (char*)data + offset, wr_size, dbg));
  fileSize += wr_size;
  left -= wr_size;
  offset += wr_size;
  
  fileSize -= (data_size - valid_size);
  printf("DataSize=%ld, ValidSize=%ld, FileSize=%ld\n",
  data_size, valid_size, fileSize);
  return s;
}

/* Assumes that data and size are block aligned */
IOStatus ZoneFile::Append(void* data, int data_size, int valid_size) {
  uint32_t left = data_size;
  uint32_t wr_size, offset = 0;
  uint32_t tmp_cap;
  IOStatus s = IOStatus::OK();

  if (!active_zone_) {
    Zone* zone = nullptr;
    s = zbd_->AllocateZone(lifetime_, &zone);
    if (!s.ok()) return s;

    if (!zone) {
      return IOStatus::NoSpace(
          "Out of space: Zone allocation failure while setting active zone");
    }

    SetActiveZone(zone);
    extent_start_ = active_zone_->wp_;
    extent_filepos_ = fileSize;
  }

  while (left) {
    if (active_zone_->capacity_ == 0) {
      PushExtent();

      s = CloseActiveZone();
      if (!s.ok()) {
        return s;
      }

      Zone* zone = nullptr;
      s = zbd_->AllocateZone(lifetime_, &zone);
      if (!s.ok()) return s;

      if (!zone) {
        return IOStatus::NoSpace(
            "Out of space: Zone allocation failure while replacing active "
            "zone");
      }

      SetActiveZone(zone);

      extent_start_ = active_zone_->wp_;
      extent_filepos_ = fileSize;
    }

    wr_size = left;
    if (wr_size > active_zone_->capacity_) wr_size = active_zone_->capacity_;

    s = active_zone_->Append((char*)data + offset, wr_size);
    if (!s.ok()) return s;

    fileSize += wr_size;
    left -= wr_size;
    offset += wr_size;
  }

  fileSize -= (data_size - valid_size);
  return s;
}

IOStatus ZoneFile::SetWriteLifeTimeHint(Env::WriteLifeTimeHint lifetime) {
  lifetime_ = lifetime;
  return IOStatus::OK();
}

void ZoneFile::ReleaseActiveZone() {
  assert(active_zone_ != nullptr);
  bool ok = active_zone_->Release();
  assert(ok);
  (void)ok;
  active_zone_ = nullptr;
}

void ZoneFile::SetActiveZone(Zone* zone) {
  // assert(active_zone_ == nullptr);
  // assert(zone->IsBusy());
  active_zone_ = zone;
}

ZonedWritableFile::ZonedWritableFile(ZonedBlockDevice* zbd, bool _buffered,
                                     std::shared_ptr<ZoneFile> zoneFile,
                                     MetadataWriter* metadata_writer) {
  wp = zoneFile->GetFileSize();
  assert(wp == 0);

  buffered = _buffered;
  block_sz = zbd->GetBlockSize();
  buffer_sz = block_sz * 256;
  buffer_pos = 0;

  zoneFile_ = zoneFile;
  

  if (buffered) {
    int ret = posix_memalign((void**)&buffer, sysconf(_SC_PAGESIZE), buffer_sz);

    if (ret) buffer = nullptr;

    assert(buffer != nullptr);
  }

  metadata_writer_ = metadata_writer;
  zoneFile_->OpenWR();
}

ZonedWritableFile::~ZonedWritableFile() {
  IOStatus s = zoneFile_->CloseWR();
  if (buffered) free(buffer);

  if (!s.ok()) {
    zoneFile_->GetZbd()->SetZoneDeferredStatus(s);
  }
}

ZonedWritableFile::MetadataWriter::~MetadataWriter() {}

IOStatus ZonedWritableFile::Truncate(uint64_t size,
                                     const IOOptions& /*options*/,
                                     IODebugContext* /*dbg*/) {
  zoneFile_->SetFileSize(size);
  return IOStatus::OK();
}

IOStatus ZonedWritableFile::Fsync(const IOOptions& /*options*/,
                                  IODebugContext* /*dbg*/) {
  IOStatus s;
  // Finish (actual write to zones) zone group
  // We need to keep going for the last footer metdata blocks.

//  Info(zoneFile_->GetZbd()->logger_, "Fsync file %s start!\n", zoneFile_->GetFilename().c_str());
  
  for(auto& thread : zoneFile_->thread_pool_){
    thread.join();
  }
  zoneFile_->thread_pool_.clear();

//  Info(zoneFile_->GetZbd()->logger_, "Fsync file %s end!\n", zoneFile_->GetFilename().c_str());

//  for(auto& zone : zoneFile_->static_zone_vec){
//    Info(zoneFile_->GetZbd()->logger_, "file %s end! zone cap = %ld \n", zoneFile_->GetFilename().c_str(), zone->capacity_);
//  }

  for(auto& zone : zoneFile_->static_zone_vec){
    zone->Finish();
  }
  zoneFile_->static_zone_vec.clear();
 
   buffer_mtx_.lock();
  s = FlushBuffer();
  buffer_mtx_.unlock();
  if (!s.ok()) {
    return s;
  }
  zoneFile_->PushExtent();
  return metadata_writer_->Persist(zoneFile_);
}

IOStatus ZonedWritableFile::Sync(const IOOptions& options,
                                 IODebugContext* dbg) {
  return Fsync(options, dbg);
}

IOStatus ZonedWritableFile::Flush(const IOOptions& /*options*/,
                                  IODebugContext* /*dbg*/) {
  return IOStatus::OK();
}

IOStatus ZonedWritableFile::RangeSync(uint64_t offset, uint64_t nbytes,
                                      const IOOptions& options,
                                      IODebugContext* dbg) {
  if (wp < offset + nbytes) return Fsync(options, dbg);

  return IOStatus::OK();
}

IOStatus ZonedWritableFile::Close(const IOOptions& options,
                                  IODebugContext* dbg) {
  Fsync(options, dbg);
  return zoneFile_->CloseWR();
}

IOStatus ZonedWritableFile::FlushBuffer() {
  uint32_t align, pad_sz = 0, wr_sz;
  IOStatus s;

  if (!buffer_pos) return IOStatus::OK();
  
//  align = buffer_pos % buffer_sz;
  align = buffer_pos % block_sz;
  if (align) pad_sz = block_sz - align;
  
  if (pad_sz) memset((char*)buffer + buffer_pos, 0x0, pad_sz);

  wr_sz = buffer_pos + pad_sz;
  s = zoneFile_->Append((char*)buffer, wr_sz, buffer_pos);
  if (!s.ok()) {
    return s;
  }

  wp += buffer_pos;
  buffer_pos = 0;

  return IOStatus::OK();
}

IOStatus ZonedWritableFile::BufferedWrite(const Slice& slice) {
  uint32_t buffer_left = buffer_sz - buffer_pos;
  uint32_t data_left = slice.size();
  char* data = (char*)slice.data();
  uint32_t tobuffer;
  int blocks, aligned_sz;
  int ret;
  void* alignbuf;
  IOStatus s;

  if (buffer_pos || data_left <= buffer_left) {
    if (data_left < buffer_left) {
      tobuffer = data_left;
    } else {
      tobuffer = buffer_left;
    }

    memcpy(buffer + buffer_pos, data, tobuffer);
    buffer_pos += tobuffer;
    data_left -= tobuffer;

    if (!data_left) return IOStatus::OK();

    data += tobuffer;
  }

  if (buffer_pos == buffer_sz) {
    s = FlushBuffer();
    if (!s.ok()) return s;
  }

  if (data_left >= buffer_sz) {
    blocks = data_left / block_sz;
    aligned_sz = block_sz * blocks;

    //malloc
    ret = posix_memalign(&alignbuf, sysconf(_SC_PAGESIZE), aligned_sz);
    if (ret) {
      return IOStatus::IOError("failed allocating alignment write buffer\n");
    }

    memcpy(alignbuf, data, aligned_sz);
    s = zoneFile_->Append(alignbuf, aligned_sz, aligned_sz);
    free(alignbuf);

    if (!s.ok()) return s;

    wp += aligned_sz;
    data_left -= aligned_sz;
    data += aligned_sz;
  }

  if (data_left) {
    memcpy(buffer, data, data_left);
    buffer_pos = data_left;
  }

  return IOStatus::OK();
}

IOStatus ZonedWritableFile::Append(const Slice& data,
                                   const IOOptions& /*options*/,
                                   IODebugContext* /*dbg*/) {
  IOStatus s;

  if (buffered) {
    buffer_mtx_.lock();
    s = BufferedWrite(data);
    buffer_mtx_.unlock();
  } else {
    s = zoneFile_->Append((void*)data.data(), data.size(), data.size());
    if (s.ok()) wp += data.size();
  }

  return s;
}


IOStatus ZonedWritableFile::PositionedAppend(const Slice& data, uint64_t offset,
                                             const IOOptions& /*options*/,
                                             IODebugContext* dbg) {
  IOStatus s;

  if (offset != wp) {
    assert(false);
    printf("offset!=wp offset=0x%lx, wp=0x%lx\n", offset, wp);
    return IOStatus::IOError("positioned append not at write pointer");
  }

  if (buffered) {
    buffer_mtx_.lock();
    s = BufferedWrite(data);
    buffer_mtx_.unlock();
  } else {
    s = zoneFile_->Append((void*)data.data(), data.size(), data.size(), dbg, smallest, largest, s_len, l_len);
    if (s.ok()){
    printf("[WRITE] ZoneFile Append Finish!!! (offset) wp=0x%lx\n", wp);
       wp += data.size();
    }
//    buffers_.push_back(dbg);
  }
  return s;
}

void ZonedWritableFile::SetWriteLifeTimeHint(Env::WriteLifeTimeHint hint) {
  zoneFile_->SetWriteLifeTimeHint(hint);
}

IOStatus ZonedSequentialFile::Read(size_t n, const IOOptions& /*options*/,
                                   Slice* result, char* scratch,
                                   IODebugContext* /*dbg*/) {
  IOStatus s;

  s = zoneFile_->PositionedRead(rp, n, result, scratch, direct_);
  if (s.ok()) rp += result->size();

  return s;
}

IOStatus ZonedSequentialFile::Skip(uint64_t n) {
  if (rp + n >= zoneFile_->GetFileSize())
    return IOStatus::InvalidArgument("Skip beyond end of file");
  rp += n;
  return IOStatus::OK();
}

IOStatus ZonedSequentialFile::PositionedRead(uint64_t offset, size_t n,
                                             const IOOptions& /*options*/,
                                             Slice* result, char* scratch,
                                             IODebugContext* /*dbg*/) {
  return zoneFile_->PositionedRead(offset, n, result, scratch, direct_);
}

IOStatus ZonedRandomAccessFile::Read(uint64_t offset, size_t n,
                                     const IOOptions& /*options*/,
                                     Slice* result, char* scratch,
                                     IODebugContext* /*dbg*/) const {
#if 1
          if(zoneFile_->GetFilename().substr(zoneFile_->GetFilename().size() - 3) == "sst") {
            return zoneFile_->PositionedRead(offset, n, result, scratch, direct_, smallest, largest, s_len, l_len);
          }
#endif
  return zoneFile_->PositionedRead(offset, n, result, scratch, direct_);
}

size_t ZoneFile::GetUniqueId(char* id, size_t max_size) {
  /* Based on the posix fs implementation */
  if (max_size < kMaxVarint64Length * 3) {
    return 0;
  }

  struct stat buf;
  int fd = zbd_->GetReadFD();
  int result = fstat(fd, &buf);
  if (result == -1) {
    return 0;
  }

  char* rid = id;
  rid = EncodeVarint64(rid, buf.st_dev);
  rid = EncodeVarint64(rid, buf.st_ino);
  rid = EncodeVarint64(rid, file_id_);
  assert(rid >= id);
  return static_cast<size_t>(rid - id);

  return 0;
}

size_t ZonedRandomAccessFile::GetUniqueId(char* id, size_t max_size) const {
  return zoneFile_->GetUniqueId(id, max_size);
}

}  // namespace ROCKSDB_NAMESPACE

#endif  // !defined(ROCKSDB_LITE) && !defined(OS_WIN)
