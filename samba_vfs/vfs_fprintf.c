/* 
 * Skeleton VFS module.  Implements dummy versions of all VFS
 * functions.
 *
 * Copyright (C) Tim Potter, 1999-2000
 * Copyright (C) Alexander Bokovoy, 2002
 * Copyright (C) Stefan (metze) Metzmacher, 2003
 * Copyright (C) Jeremy Allison 2009
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *  
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *  
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */


#include "../source3/include/includes.h"

/* PLEASE,PLEASE READ THE VFS MODULES CHAPTER OF THE 
   SAMBA DEVELOPERS GUIDE!!!!!!
 */

/* If you take this file as template for your module
 * you must re-implement every function.
 */

static int skel_connect(vfs_handle_struct *handle,  const char *service, const char *user)    
{
	fprintf(stderr, "In skel_connect\n");
	return 0;
}

static void skel_disconnect(vfs_handle_struct *handle)
{
	fprintf(stderr, "In skel_disconnect\n");
	;
}

static uint64_t skel_disk_free(vfs_handle_struct *handle,  const char *path,
	bool small_query, uint64_t *bsize,
	uint64_t *dfree, uint64_t *dsize)
{
	fprintf(stderr, "In skel_disconnect\n");
	*bsize = 0;
	*dfree = 0;
	*dsize = 0;
	return 0;
}

static int skel_get_quota(vfs_handle_struct *handle,  enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dq)
{
	fprintf(stderr, "In skel_get_quota\n");
	errno = ENOSYS;
	return -1;
}

static int skel_set_quota(vfs_handle_struct *handle,  enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dq)
{
	fprintf(stderr, "In skel_set_quota\n");
	errno = ENOSYS;
	return -1;
}

static int skel_get_shadow_copy_data(vfs_handle_struct *handle, files_struct *fsp, struct shadow_copy_data *shadow_copy_data, bool labels)
{
	fprintf(stderr, "In skel_get_shadow_copy_data\n");
	errno = ENOSYS;
	return -1;
}

static int skel_statvfs(struct vfs_handle_struct *handle, const char *path, struct vfs_statvfs_struct *statbuf)
{
	fprintf(stderr, "In skel_statvfs\n");
	errno = ENOSYS;
	return -1;
}

static uint32_t skel_fs_capabilities(struct vfs_handle_struct *handle, enum timestamp_set_resolution *p_ts_res)
{
	fprintf(stderr, "In skel_fs_capabilities\n");
	return 0;
}

static NTSTATUS skel_get_dfs_referrals(struct vfs_handle_struct *handle,
				       struct dfs_GetDFSReferral *r)
{
	fprintf(stderr, "In skel_fs_capabilities\n");
	return NT_STATUS_NOT_IMPLEMENTED;
}

static DIR *skel_opendir(vfs_handle_struct *handle,  const char *fname, const char *mask, uint32 attr)
{
	fprintf(stderr, "In skel_opendir\n");
	return NULL;
}

static DIR *skel_fdopendir(vfs_handle_struct *handle, files_struct *fsp, const char *mask, uint32 attr)
{
	fprintf(stderr, "In skel_fdopendir\n");
	return NULL;
}

static struct dirent *skel_readdir(vfs_handle_struct *handle,
				       DIR *dirp,
				       SMB_STRUCT_STAT *sbuf)
{
	fprintf(stderr, "In skel_fdopendir\n");
	return NULL;
}

static void skel_seekdir(vfs_handle_struct *handle,  DIR *dirp, long offset)
{
	fprintf(stderr, "In skel_seekdir\n");
	;
}

static long skel_telldir(vfs_handle_struct *handle,  DIR *dirp)
{
	fprintf(stderr, "In skel_telldir\n");
	return (long)-1;
}

static void skel_rewind_dir(vfs_handle_struct *handle, DIR *dirp)
{
	fprintf(stderr, "In skel_rewind_dir\n");
	;
}

static int skel_mkdir(vfs_handle_struct *handle,  const char *path, mode_t mode)
{
	fprintf(stderr, "In skel_mkdir\n");
	errno = ENOSYS;
	return -1;
}

static int skel_rmdir(vfs_handle_struct *handle,  const char *path)
{
	fprintf(stderr, "In skel_rmdir\n");
	errno = ENOSYS;
	return -1;
}

static int skel_closedir(vfs_handle_struct *handle,  DIR *dir)
{
	fprintf(stderr, "In skel_closedir\n");
	errno = ENOSYS;
	return -1;
}

static void skel_init_search_op(struct vfs_handle_struct *handle, DIR *dirp)
{
	fprintf(stderr, "In skel_init_search_op\n");
	;
}

static int skel_open(vfs_handle_struct *handle, struct smb_filename *smb_fname,
		     files_struct *fsp, int flags, mode_t mode)
{
	fprintf(stderr, "In skel_init_search_op\n");
	errno = ENOSYS;
	return -1;
}

static NTSTATUS skel_create_file(struct vfs_handle_struct *handle,
                                struct smb_request *req,
                                uint16_t root_dir_fid,
                                struct smb_filename *smb_fname,
                                uint32_t access_mask,
                                uint32_t share_access,
                                uint32_t create_disposition,
                                uint32_t create_options,
                                uint32_t file_attributes,
                                uint32_t oplock_request,
                                uint64_t allocation_size,
				uint32_t private_flags,
                                struct security_descriptor *sd,
                                struct ea_list *ea_list,
                                files_struct **result,
                                int *pinfo)
{
	fprintf(stderr, "In skel_init_search_op\n");
	return NT_STATUS_NOT_IMPLEMENTED;
}

static int skel_close_fn(vfs_handle_struct *handle, files_struct *fsp)
{
	fprintf(stderr, "In skel_close_fn\n");
	errno = ENOSYS;
	return -1;
}

static ssize_t skel_vfs_read(vfs_handle_struct *handle, files_struct *fsp, void *data, size_t n)
{
	fprintf(stderr, "In skel_vfs_read\n");
	errno = ENOSYS;
	return -1;
}

static ssize_t skel_pread(vfs_handle_struct *handle, files_struct *fsp, void *data, size_t n, off_t offset)
{
	fprintf(stderr, "In skel_pread\n");
	errno = ENOSYS;
	return -1;
}

static struct tevent_req *skel_pread_send(struct vfs_handle_struct *handle,
					  TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct files_struct *fsp,
					  void *data, size_t n, off_t offset)
{
	fprintf(stderr, "In skel_pread\n");
	return NULL;
}

static ssize_t skel_pread_recv(struct tevent_req *req, int *err)
{
	fprintf(stderr, "In skel_pread_recv\n");
	*err = ENOSYS;
	return -1;
}

static ssize_t skel_write(vfs_handle_struct *handle, files_struct *fsp, const void *data, size_t n)
{
	fprintf(stderr, "In skel_write\n");
	errno = ENOSYS;
	return -1;
}

static ssize_t skel_pwrite(vfs_handle_struct *handle, files_struct *fsp, const void *data, size_t n, off_t offset)
{
	fprintf(stderr, "In skel_pwrite\n");
	errno = ENOSYS;
	return -1;
}

static struct tevent_req *skel_pwrite_send(struct vfs_handle_struct *handle,
					   TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct files_struct *fsp,
					   const void *data,
					   size_t n, off_t offset)
{
	fprintf(stderr, "In skel_pwrite\n");
	return NULL;
}

static ssize_t skel_pwrite_recv(struct tevent_req *req, int *err)
{
	fprintf(stderr, "In skel_pwrite_recv\n");
	*err = ENOSYS;
	return -1;
}

static off_t skel_lseek(vfs_handle_struct *handle, files_struct *fsp, off_t offset, int whence)
{
	fprintf(stderr, "In skel_lseek\n");
	errno = ENOSYS;
	return (off_t)-1;
}

static ssize_t skel_sendfile(vfs_handle_struct *handle, int tofd, files_struct *fromfsp, const DATA_BLOB *hdr, off_t offset, size_t n)
{
	fprintf(stderr, "In skel_sendfile\n");
	errno = ENOSYS;
	return -1;
}

static ssize_t skel_recvfile(vfs_handle_struct *handle, int fromfd, files_struct *tofsp, off_t offset, size_t n)
{
	fprintf(stderr, "In skel_recvfile\n");
	errno = ENOSYS;
	return -1;
}

static int skel_rename(vfs_handle_struct *handle,
		       const struct smb_filename *smb_fname_src,
		       const struct smb_filename *smb_fname_dst)
{
	fprintf(stderr, "In skel_recvfile\n");
	errno = ENOSYS;
	return -1;
}

static int skel_fsync(vfs_handle_struct *handle, files_struct *fsp)
{
	fprintf(stderr, "In skel_fsync\n");
	errno = ENOSYS;
	return -1;
}

static struct tevent_req *skel_fsync_send(struct vfs_handle_struct *handle,
					  TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct files_struct *fsp)
{
	fprintf(stderr, "In skel_fsync\n");
	return NULL;
}

static int skel_fsync_recv(struct tevent_req *req, int *err)
{
	fprintf(stderr, "In skel_fsync_recv\n");
	*err = ENOSYS;
	return -1;
}

static int skel_stat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
	fprintf(stderr, "In skel_stat\n");
	errno = ENOSYS;
	return -1;
}

static int skel_fstat(vfs_handle_struct *handle, files_struct *fsp, SMB_STRUCT_STAT *sbuf)
{
	fprintf(stderr, "In skel_fstat\n");
	errno = ENOSYS;
	return -1;
}

static int skel_lstat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
	fprintf(stderr, "In skel_lstat\n");
	errno = ENOSYS;
	return -1;
}

static uint64_t skel_get_alloc_size(struct vfs_handle_struct *handle, struct files_struct *fsp, const SMB_STRUCT_STAT *sbuf)
{
	fprintf(stderr, "In skel_get_alloc_size\n");
	errno = ENOSYS;
	return -1;
}

static int skel_unlink(vfs_handle_struct *handle,
		       const struct smb_filename *smb_fname)
{
	fprintf(stderr, "In skel_get_alloc_size\n");
	errno = ENOSYS;
	return -1;
}

static int skel_chmod(vfs_handle_struct *handle,  const char *path, mode_t mode)
{
	fprintf(stderr, "In skel_chmod\n");
	errno = ENOSYS;
	return -1;
}

static int skel_fchmod(vfs_handle_struct *handle, files_struct *fsp, mode_t mode)
{
	fprintf(stderr, "In skel_fchmod\n");
	errno = ENOSYS;
	return -1;
}

static int skel_chown(vfs_handle_struct *handle,  const char *path, uid_t uid, gid_t gid)
{
	fprintf(stderr, "In skel_chown\n");
	errno = ENOSYS;
	return -1;
}

static int skel_fchown(vfs_handle_struct *handle, files_struct *fsp, uid_t uid, gid_t gid)
{
	fprintf(stderr, "In skel_fchown\n");
	errno = ENOSYS;
	return -1;
}

static int skel_lchown(vfs_handle_struct *handle,  const char *path, uid_t uid, gid_t gid)
{
	fprintf(stderr, "In skel_lchown\n");
	errno = ENOSYS;
	return -1;
}

static int skel_chdir(vfs_handle_struct *handle,  const char *path)
{
	fprintf(stderr, "In skel_chdir\n");
	errno = ENOSYS;
	return -1;
}

static char *skel_getwd(vfs_handle_struct *handle)
{
	fprintf(stderr, "In skel_getwd\n");
	errno = ENOSYS;
	return NULL;
}

static int skel_ntimes(vfs_handle_struct *handle,
		       const struct smb_filename *smb_fname,
		       struct smb_file_time *ft)
{
	fprintf(stderr, "In skel_getwd\n");
	errno = ENOSYS;
	return -1;
}

static int skel_ftruncate(vfs_handle_struct *handle, files_struct *fsp, off_t offset)
{
	fprintf(stderr, "In skel_ftruncate\n");
	errno = ENOSYS;
	return -1;
}

static int skel_fallocate(vfs_handle_struct *handle, files_struct *fsp,
			enum vfs_fallocate_mode mode,
			off_t offset, off_t len)
{
	fprintf(stderr, "In skel_ftruncate\n");
	errno = ENOSYS;
	return -1;
}

static bool skel_lock(vfs_handle_struct *handle, files_struct *fsp, int op, off_t offset, off_t count, int type)
{
	fprintf(stderr, "In skel_lock\n");
	errno = ENOSYS;
	return false;
}

static int skel_kernel_flock(struct vfs_handle_struct *handle, struct files_struct *fsp, uint32 share_mode, uint32 access_mask)
{
	fprintf(stderr, "In skel_kernel_flock\n");
	errno = ENOSYS;
	return -1;
}

static int skel_linux_setlease(struct vfs_handle_struct *handle, struct files_struct *fsp, int leasetype)
{
	fprintf(stderr, "In skel_linux_setlease\n");
	errno = ENOSYS;
	return -1;
}

static bool skel_getlock(vfs_handle_struct *handle, files_struct *fsp, off_t *poffset, off_t *pcount, int *ptype, pid_t *ppid)
{
	fprintf(stderr, "In skel_getlock\n");
	errno = ENOSYS;
	return false;
}

static int skel_symlink(vfs_handle_struct *handle,  const char *oldpath, const char *newpath)
{
	fprintf(stderr, "In skel_symlink\n");
	errno = ENOSYS;
	return -1;
}

static int skel_vfs_readlink(vfs_handle_struct *handle, const char *path, char *buf, size_t bufsiz)
{
	fprintf(stderr, "In skel_vfs_readlink\n");
	errno = ENOSYS;
	return -1;
}

static int skel_link(vfs_handle_struct *handle,  const char *oldpath, const char *newpath)
{
	fprintf(stderr, "In skel_link\n");
	errno = ENOSYS;
	return -1;
}

static int skel_mknod(vfs_handle_struct *handle,  const char *path, mode_t mode, SMB_DEV_T dev)
{
	fprintf(stderr, "In skel_mknod\n");
	errno = ENOSYS;
	return -1;
}

static char *skel_realpath(vfs_handle_struct *handle,  const char *path)
{
#define FAKE_REALPATH "/__does_not_exist__"
    char *p;
	fprintf(stderr, "In skel_realpath\n");
    p = malloc(sizeof(FAKE_REALPATH));
    strncpy(p, FAKE_REALPATH, sizeof(FAKE_REALPATH) - 1);
	return p;
}

static NTSTATUS skel_notify_watch(struct vfs_handle_struct *handle,
	    struct sys_notify_context *ctx,
	    const char *path,
	    uint32_t *filter,
	    uint32_t *subdir_filter,
	    void (*callback)(struct sys_notify_context *ctx, void *private_data, struct notify_event *ev),
	    void *private_data, void *handle_p)
{
	fprintf(stderr, "In skel_realpath\n");
	return NT_STATUS_NOT_IMPLEMENTED;
}

static int skel_chflags(vfs_handle_struct *handle,  const char *path, uint flags)
{
	fprintf(stderr, "In skel_chflags\n");
	errno = ENOSYS;
	return -1;
}

static struct file_id skel_file_id_create(vfs_handle_struct *handle,
					  const SMB_STRUCT_STAT *sbuf)
{
	fprintf(stderr, "In skel_chflags\n");
	struct file_id id;
	ZERO_STRUCT(id);
	errno = ENOSYS;
	return id;
}

static NTSTATUS skel_streaminfo(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				const char *fname,
				TALLOC_CTX *mem_ctx,
				unsigned int *num_streams,
				struct stream_struct **streams)
{
	fprintf(stderr, "In skel_chflags\n");
	return NT_STATUS_NOT_IMPLEMENTED;
}

static int skel_get_real_filename(struct vfs_handle_struct *handle,
				const char *path,
				const char *name,
				TALLOC_CTX *mem_ctx,
				char **found_name)
{
	fprintf(stderr, "In skel_chflags\n");
	errno = ENOSYS;
	return -1;
}

static const char *skel_connectpath(struct vfs_handle_struct *handle,
				const char *filename)
{
	fprintf(stderr, "In skel_chflags\n");
	errno = ENOSYS;
	return NULL;
}

static NTSTATUS skel_brl_lock_windows(struct vfs_handle_struct *handle,
				struct byte_range_lock *br_lck,
				struct lock_struct *plock,
				bool blocking_lock,
				struct blocking_lock_record *blr)
{
	fprintf(stderr, "In skel_chflags\n");
	return NT_STATUS_NOT_IMPLEMENTED;
}

static bool skel_brl_unlock_windows(struct vfs_handle_struct *handle,
				struct messaging_context *msg_ctx,
				struct byte_range_lock *br_lck,
				const struct lock_struct *plock)
{
	fprintf(stderr, "In skel_chflags\n");
	errno = ENOSYS;
	return false;
}

static bool skel_brl_cancel_windows(struct vfs_handle_struct *handle,
				struct byte_range_lock *br_lck,
				struct lock_struct *plock,
				struct blocking_lock_record *blr)
{
	fprintf(stderr, "In skel_chflags\n");
	errno = ENOSYS;
	return false;
}

static bool skel_strict_lock(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				struct lock_struct *plock)
{
	fprintf(stderr, "In skel_chflags\n");
	errno = ENOSYS;
	return false;
}

static void skel_strict_unlock(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				struct lock_struct *plock)
{
	fprintf(stderr, "In skel_chflags\n");
	;
}

static NTSTATUS skel_translate_name(struct vfs_handle_struct *handle,
				const char *mapped_name,
				enum vfs_translate_direction direction,
				TALLOC_CTX *mem_ctx,
				char **pmapped_name)
{
	fprintf(stderr, "In skel_chflags\n");
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS skel_fsctl(struct vfs_handle_struct *handle,
			struct files_struct *fsp,
			TALLOC_CTX *ctx,
			uint32_t function,
			uint16_t req_flags,  /* Needed for UNICODE ... */
			const uint8_t *_in_data,
			uint32_t in_len,
			uint8_t **_out_data,
			uint32_t max_out_len,
			uint32_t *out_len)
{
	fprintf(stderr, "In skel_chflags\n");
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS skel_fget_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
				 uint32 security_info,
				 TALLOC_CTX *mem_ctx,
				 struct security_descriptor **ppdesc)
{
	fprintf(stderr, "In skel_chflags\n");
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS skel_get_nt_acl(vfs_handle_struct *handle,
				const char *name, uint32 security_info,
				TALLOC_CTX *mem_ctx,
				struct security_descriptor **ppdesc)
{
	fprintf(stderr, "In skel_chflags\n");
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS skel_fset_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
	uint32 security_info_sent, const struct security_descriptor *psd)
{
	fprintf(stderr, "In skel_chflags\n");
	return NT_STATUS_NOT_IMPLEMENTED;
}

static int skel_chmod_acl(vfs_handle_struct *handle,  const char *name, mode_t mode)
{
	fprintf(stderr, "In skel_chmod_acl\n");
	errno = ENOSYS;
	return -1;
}

static int skel_fchmod_acl(vfs_handle_struct *handle, files_struct *fsp, mode_t mode)
{
	fprintf(stderr, "In skel_fchmod_acl\n");
	errno = ENOSYS;
	return -1;
}

static SMB_ACL_T skel_sys_acl_get_file(vfs_handle_struct *handle,
				       const char *path_p,
				       SMB_ACL_TYPE_T type,
				       TALLOC_CTX *mem_ctx)
{
	fprintf(stderr, "In skel_fchmod_acl\n");
	errno = ENOSYS;
	return (SMB_ACL_T)NULL;
}

static SMB_ACL_T skel_sys_acl_get_fd(vfs_handle_struct *handle,
				     files_struct *fsp,
				     TALLOC_CTX *mem_ctx)
{
	fprintf(stderr, "In skel_fchmod_acl\n");
	errno = ENOSYS;
	return (SMB_ACL_T)NULL;
}

static int skel_sys_acl_blob_get_file(vfs_handle_struct *handle,  const char *path_p, TALLOC_CTX *mem_ctx, char **blob_description, DATA_BLOB *blob)
{
	fprintf(stderr, "In skel_sys_acl_blob_get_file\n");
	errno = ENOSYS;
	return -1;
}

static int skel_sys_acl_blob_get_fd(vfs_handle_struct *handle, files_struct *fsp, TALLOC_CTX *mem_ctx, char **blob_description, DATA_BLOB *blob)
{
	fprintf(stderr, "In skel_sys_acl_blob_get_fd\n");
	errno = ENOSYS;
	return -1;
}

static int skel_sys_acl_set_file(vfs_handle_struct *handle,  const char *name, SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl)
{
	fprintf(stderr, "In skel_sys_acl_set_file\n");
	errno = ENOSYS;
	return -1;
}

static int skel_sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp, SMB_ACL_T theacl)
{
	fprintf(stderr, "In skel_sys_acl_set_fd\n");
	errno = ENOSYS;
	return -1;
}

static int skel_sys_acl_delete_def_file(vfs_handle_struct *handle,  const char *path)
{
	fprintf(stderr, "In skel_sys_acl_delete_def_file\n");
	errno = ENOSYS;
	return -1;
}

static ssize_t skel_getxattr(vfs_handle_struct *handle, const char *path, const char *name, void *value, size_t size)
{
	fprintf(stderr, "In skel_getxattr\n");
	errno = ENOSYS;
	return -1;
}

static ssize_t skel_fgetxattr(vfs_handle_struct *handle, struct files_struct *fsp, const char *name, void *value, size_t size)
{
	fprintf(stderr, "In skel_fgetxattr\n");
	errno = ENOSYS;
	return -1;
}

static ssize_t skel_listxattr(vfs_handle_struct *handle, const char *path, char *list, size_t size)
{
	fprintf(stderr, "In skel_listxattr\n");
	errno = ENOSYS;
	return -1;
}

static ssize_t skel_flistxattr(vfs_handle_struct *handle, struct files_struct *fsp, char *list, size_t size)
{
	fprintf(stderr, "In skel_flistxattr\n");
	errno = ENOSYS;
	return -1;
}

static int skel_removexattr(vfs_handle_struct *handle, const char *path, const char *name)
{
	fprintf(stderr, "In skel_removexattr\n");
	errno = ENOSYS;
	return -1;
}

static int skel_fremovexattr(vfs_handle_struct *handle, struct files_struct *fsp, const char *name)
{
	fprintf(stderr, "In skel_fremovexattr\n");
	errno = ENOSYS;
	return -1;
        return SMB_VFS_NEXT_FREMOVEXATTR(handle, fsp, name);
}

static int skel_setxattr(vfs_handle_struct *handle, const char *path, const char *name, const void *value, size_t size, int flags)
{
	fprintf(stderr, "In skel_setxattr\n");
	errno = ENOSYS;
	return -1;
}

static int skel_fsetxattr(vfs_handle_struct *handle, struct files_struct *fsp, const char *name, const void *value, size_t size, int flags)
{
	fprintf(stderr, "In skel_fsetxattr\n");
	errno = ENOSYS;
	return -1;
}

static bool skel_aio_force(struct vfs_handle_struct *handle, struct files_struct *fsp)
{
	fprintf(stderr, "In skel_aio_force\n");
	errno = ENOSYS;
	return false;
}

static bool skel_is_offline(struct vfs_handle_struct *handle, const struct smb_filename *fname, SMB_STRUCT_STAT *sbuf)
{
	fprintf(stderr, "In skel_is_offline\n");
	errno = ENOSYS;
	return false;
}

static int skel_set_offline(struct vfs_handle_struct *handle, const struct smb_filename *fname)
{
	fprintf(stderr, "In skel_set_offline\n");
	errno = ENOSYS;
	return -1;
}

/* VFS operations structure */

struct vfs_fn_pointers skel_opaque_fns = {
	/* Disk operations */

	.connect_fn = skel_connect,
	.disconnect_fn = skel_disconnect,
	.disk_free_fn = skel_disk_free,
	.get_quota_fn = skel_get_quota,
	.set_quota_fn = skel_set_quota,
	.get_shadow_copy_data_fn = skel_get_shadow_copy_data,
	.statvfs_fn = skel_statvfs,
	.fs_capabilities_fn = skel_fs_capabilities,
	.get_dfs_referrals_fn = skel_get_dfs_referrals,

	/* Directory operations */

	.opendir_fn = skel_opendir,
	.fdopendir_fn = skel_fdopendir,
	.readdir_fn = skel_readdir,
	.seekdir_fn = skel_seekdir,
	.telldir_fn = skel_telldir,
	.rewind_dir_fn = skel_rewind_dir,
	.mkdir_fn = skel_mkdir,
	.rmdir_fn = skel_rmdir,
	.closedir_fn = skel_closedir,
	.init_search_op_fn = skel_init_search_op,

	/* File operations */

	.open_fn = skel_open,
	.create_file_fn = skel_create_file,
	.close_fn = skel_close_fn,
	.read_fn = skel_vfs_read,
	.pread_fn = skel_pread,
	.pread_send_fn = skel_pread_send,
	.pread_recv_fn = skel_pread_recv,
	.write_fn = skel_write,
	.pwrite_fn = skel_pwrite,
	.pwrite_send_fn = skel_pwrite_send,
	.pwrite_recv_fn = skel_pwrite_recv,
	.lseek_fn = skel_lseek,
	.sendfile_fn = skel_sendfile,
	.recvfile_fn = skel_recvfile,
	.rename_fn = skel_rename,
	.fsync_fn = skel_fsync,
	.fsync_send_fn = skel_fsync_send,
	.fsync_recv_fn = skel_fsync_recv,
	.stat_fn = skel_stat,
	.fstat_fn = skel_fstat,
	.lstat_fn = skel_lstat,
	.get_alloc_size_fn = skel_get_alloc_size,
	.unlink_fn = skel_unlink,
	.chmod_fn = skel_chmod,
	.fchmod_fn = skel_fchmod,
	.chown_fn = skel_chown,
	.fchown_fn = skel_fchown,
	.lchown_fn = skel_lchown,
	.chdir_fn = skel_chdir,
	.getwd_fn = skel_getwd,
	.ntimes_fn = skel_ntimes,
	.ftruncate_fn = skel_ftruncate,
	.fallocate_fn = skel_fallocate,
	.lock_fn = skel_lock,
	.kernel_flock_fn = skel_kernel_flock,
	.linux_setlease_fn = skel_linux_setlease,
	.getlock_fn = skel_getlock,
	.symlink_fn = skel_symlink,
	.readlink_fn = skel_vfs_readlink,
	.link_fn = skel_link,
	.mknod_fn = skel_mknod,
	.realpath_fn = skel_realpath,
	.notify_watch_fn = skel_notify_watch,
	.chflags_fn = skel_chflags,
	.file_id_create_fn = skel_file_id_create,

	.streaminfo_fn = skel_streaminfo,
	.get_real_filename_fn = skel_get_real_filename,
	.connectpath_fn = skel_connectpath,
	.brl_lock_windows_fn = skel_brl_lock_windows,
	.brl_unlock_windows_fn = skel_brl_unlock_windows,
	.brl_cancel_windows_fn = skel_brl_cancel_windows,
	.strict_lock_fn = skel_strict_lock,
	.strict_unlock_fn = skel_strict_unlock,
	.translate_name_fn = skel_translate_name,
	.fsctl_fn = skel_fsctl,

	/* NT ACL operations. */

	.fget_nt_acl_fn = skel_fget_nt_acl,
	.get_nt_acl_fn = skel_get_nt_acl,
	.fset_nt_acl_fn = skel_fset_nt_acl,

	/* POSIX ACL operations. */

	.chmod_acl_fn = skel_chmod_acl,
	.fchmod_acl_fn = skel_fchmod_acl,

	.sys_acl_get_file_fn = skel_sys_acl_get_file,
	.sys_acl_get_fd_fn = skel_sys_acl_get_fd,
	.sys_acl_blob_get_file_fn = skel_sys_acl_blob_get_file,
	.sys_acl_blob_get_fd_fn = skel_sys_acl_blob_get_fd,
	.sys_acl_set_file_fn = skel_sys_acl_set_file,
	.sys_acl_set_fd_fn = skel_sys_acl_set_fd,
	.sys_acl_delete_def_file_fn = skel_sys_acl_delete_def_file,


	/* EA operations. */
	.getxattr_fn = skel_getxattr,
	.fgetxattr_fn = skel_fgetxattr,
	.listxattr_fn = skel_listxattr,
	.flistxattr_fn = skel_flistxattr,
	.removexattr_fn = skel_removexattr,
	.fremovexattr_fn = skel_fremovexattr,
	.setxattr_fn = skel_setxattr,
	.fsetxattr_fn = skel_fsetxattr,

	/* aio operations */
	.aio_force_fn = skel_aio_force,

	/* offline operations */
	.is_offline_fn = skel_is_offline,
	.set_offline_fn = skel_set_offline
};

NTSTATUS vfs_je_init(void)
{
	fprintf(stderr, "In vfs_je_init\n");
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "je", &skel_opaque_fns);
}
