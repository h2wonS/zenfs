// Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved.
// Copyright (c) 2019-present, Western Digital Corporation
//  This source code is licensed under both the GPLv2 (found in the
//  COPYING file in the root directory) and Apache 2.0 License
//  (found in the LICENSE.Apache file in the root directory).

#pragma once

#if !defined(ROCKSDB_LITE) && defined(OS_LINUX)

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>
#include <thread>

#include "rocksdb/file_system.h"
#include "rocksdb/io_status.h"
#include "zbd_zenfs.h"

namespace ROCKSDB_NAMESPACE {

class ZoneExtent {
 public:
  uint64_t start_;
  uint32_t length_;
  Zone* zone_;
  char* key_smallest_;
  bool isValidkey_;
  int id_;

  explicit ZoneExtent(uint64_t start, uint32_t length, Zone* zone, char* key_smallest, bool isValidkey, int id);

  Status DecodeFrom(Slice* input);
  void EncodeTo(std::string* output);
  void EncodeJson(std::ostream& json_stream);
};

class ZoneFile {
 public:
  // write (arith), read if ( 3 < nr_threads.load())
  std::atomic<int> nr_threads;
  std::vector<Zone*> static_zone_vec;
  std::atomic<int> zone_vec_lock[22];
  std::atomic<int> position; 
 protected:
  ZonedBlockDevice* zbd_;
  std::vector<ZoneExtent*> extents_;
  Zone* active_zone_;
  uint64_t extent_start_;
  uint64_t extent_filepos_;

  Env::WriteLifeTimeHint lifetime_;
  uint64_t fileSize;
  std::string filename_;
  uint64_t file_id_;

  uint32_t nr_synced_extents_;
  bool open_for_wr_ = false;
  time_t m_time_;

 public:
  std::string getFilename() {
    return filename_;
  };

  void setExtentKeyvalid() {
    extents_.back()->isValidkey_ = true;
  }

  void setExtentID() {
    extents_.back()->id_ = static_cast<int>(extents_.size());
  }

  explicit ZoneFile(ZonedBlockDevice* zbd, std::string filename,
                    uint64_t file_id_);

  virtual ~ZoneFile();

  void OpenWR();
  IOStatus CloseWR();
  bool IsOpenForWR();
  IOStatus Append(void* data, int data_size, int valid_size, IODebugContext* dbg,
                  char* smallest, int s_len);
  IOStatus Append(void* data, int data_size, int valid_size);
  IOStatus SetWriteLifeTimeHint(Env::WriteLifeTimeHint lifetime);
  std::string GetFilename();
  void Rename(std::string name);
  time_t GetFileModificationTime();
  void SetFileModificationTime(time_t mt);
  uint64_t GetFileSize();
  void SetFileSize(uint64_t sz);

  uint32_t GetBlockSize() { return zbd_->GetBlockSize(); }
  ZonedBlockDevice* GetZbd() { return zbd_; }
  std::vector<ZoneExtent*> GetExtents() { return extents_; }
  Env::WriteLifeTimeHint GetWriteLifeTimeHint() { return lifetime_; }
  IOStatus PositionedRead(uint64_t offset, size_t n, Slice* result,
                          char* scratch, bool direct);
  ZoneExtent* GetExtent(uint64_t file_offset, uint64_t* dev_offset);
  void PushExtent2(size_t wr_size, char* smallest, int s_len);
  void PushExtent();

  void EncodeTo(std::string* output, uint32_t extent_start);
  void EncodeUpdateTo(std::string* output) {
    EncodeTo(output, nr_synced_extents_);
  };
  void EncodeSnapshotTo(std::string* output) { EncodeTo(output, 0); };
  void EncodeJson(std::ostream& json_stream);
  void MetadataSynced() { nr_synced_extents_ = extents_.size(); };

  Status DecodeFrom(Slice* input);
  Status MergeUpdate(std::shared_ptr<ZoneFile> update);

  uint64_t GetID() { return file_id_; }
  size_t GetUniqueId(char* id, size_t max_size);

  std::vector<std::thread> thread_pool_;

 private:
  void ReleaseActiveZone();
  void SetActiveZone(Zone* zone);
  IOStatus CloseActiveZone();
  std::shared_ptr<ZenFSMetrics> GetZBDMetrics() { return zbd_->GetMetrics(); }
};

class ZonedWritableFile : public FSWritableFile {
 public:
  /* Interface for persisting metadata for files */
  class MetadataWriter {
   public:
    virtual ~MetadataWriter();
    virtual IOStatus Persist(std::shared_ptr<ZoneFile> zoneFile) = 0;
  };

  explicit ZonedWritableFile(ZonedBlockDevice* zbd, bool buffered,
                             std::shared_ptr<ZoneFile> zoneFile,
                             MetadataWriter* metadata_writer = nullptr);
  virtual ~ZonedWritableFile();

  virtual IOStatus Append(const Slice& data, const IOOptions& options,
                          IODebugContext* dbg) override;
  virtual IOStatus Append(const Slice& data, const IOOptions& opts,
                          const DataVerificationInfo& /* verification_info */,
                          IODebugContext* dbg) override {
    return Append(data, opts, dbg);
  }
  virtual IOStatus PositionedAppend(const Slice& data, uint64_t offset,
                                    const IOOptions& options,
                                    IODebugContext* dbg) override;
  virtual IOStatus PositionedAppend(
      const Slice& data, uint64_t offset, const IOOptions& opts,
      const DataVerificationInfo& /* verification_info */,
      IODebugContext* dbg) override {
    return PositionedAppend(data, offset, opts, dbg);
  }

  virtual IOStatus PositionedAppend(
      const Slice& data, uint64_t offset, const IOOptions& opts,
      char* smallest, int s_len, /* key range_info */
      IODebugContext* dbg) override {
    return PositionedAppend(data, offset, opts, dbg);
  }
 
  virtual IOStatus Truncate(uint64_t size, const IOOptions& options,
                            IODebugContext* dbg) override;
  virtual IOStatus Close(const IOOptions& options,
                         IODebugContext* dbg) override;
  virtual IOStatus Flush(const IOOptions& options,
                         IODebugContext* dbg) override;
  virtual IOStatus Sync(const IOOptions& options, IODebugContext* dbg) override;
  virtual IOStatus RangeSync(uint64_t offset, uint64_t nbytes,
                             const IOOptions& options,
                             IODebugContext* dbg) override;
  virtual IOStatus Fsync(const IOOptions& options,
                         IODebugContext* dbg) override;
  bool use_direct_io() const override { return !buffered; }
  bool IsSyncThreadSafe() const override { return true; };
  size_t GetRequiredBufferAlignment() const override {
    return zoneFile_->GetBlockSize();
  }
  void SetWriteLifeTimeHint(Env::WriteLifeTimeHint hint) override;
  virtual Env::WriteLifeTimeHint GetWriteLifeTimeHint() override {
    return zoneFile_->GetWriteLifeTimeHint();
  }
 
 private:
  IOStatus BufferedWrite(const Slice& data);
  IOStatus FlushBuffer();

  bool buffered;
  char* buffer;
  size_t buffer_sz;
  uint32_t block_sz;
  uint32_t buffer_pos;
  uint64_t wp;
  int write_temp;

  std::shared_ptr<ZoneFile> zoneFile_;
  MetadataWriter* metadata_writer_;

  std::mutex buffer_mtx_;
};

class ZonedSequentialFile : public FSSequentialFile {
 private:
  std::shared_ptr<ZoneFile> zoneFile_;
  uint64_t rp;
  bool direct_;

 public:
  explicit ZonedSequentialFile(std::shared_ptr<ZoneFile> zoneFile,
                               const FileOptions& file_opts)
      : zoneFile_(zoneFile), rp(0), direct_(file_opts.use_direct_reads) {}

  IOStatus Read(size_t n, const IOOptions& options, Slice* result,
                char* scratch, IODebugContext* dbg) override;
  IOStatus PositionedRead(uint64_t offset, size_t n, const IOOptions& options,
                          Slice* result, char* scratch,
                          IODebugContext* dbg) override;
  IOStatus Skip(uint64_t n) override;

  bool use_direct_io() const override { return direct_; };

  size_t GetRequiredBufferAlignment() const override {
    return zoneFile_->GetBlockSize();
  }

  IOStatus InvalidateCache(size_t /*offset*/, size_t /*length*/) override {
    return IOStatus::OK();
  }
};

class ZonedRandomAccessFile : public FSRandomAccessFile {
 private:
  std::shared_ptr<ZoneFile> zoneFile_;
  bool direct_;

 public:
  explicit ZonedRandomAccessFile(std::shared_ptr<ZoneFile> zoneFile,
                                 const FileOptions& file_opts)
      : zoneFile_(zoneFile), direct_(file_opts.use_direct_reads) {}

  IOStatus Read(uint64_t offset, size_t n, const IOOptions& options,
                Slice* result, char* scratch,
                IODebugContext* dbg) const override;

  IOStatus Prefetch(uint64_t /*offset*/, size_t /*n*/,
                    const IOOptions& /*options*/,
                    IODebugContext* /*dbg*/) override {
    return IOStatus::OK();
  }

  bool use_direct_io() const override { return direct_; }

  size_t GetRequiredBufferAlignment() const override {
    return zoneFile_->GetBlockSize();
  }

  IOStatus InvalidateCache(size_t /*offset*/, size_t /*length*/) override {
    return IOStatus::OK();
  }

  size_t GetUniqueId(char* id, size_t max_size) const override;
};

}  // namespace ROCKSDB_NAMESPACE

#endif  // !defined(ROCKSDB_LITE) && defined(OS_LINUX)
