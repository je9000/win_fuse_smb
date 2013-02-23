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
#include "../source3/smbd/proto.h"
#include "../source3/locking/proto.h"
#include "../libcli/security/security.h"
#include <dirent.h>
#include <Python.h>

#define E_INTERNAL ENOMEM

/* PLEASE,PLEASE READ THE VFS MODULES CHAPTER OF THE 
   SAMBA DEVELOPERS GUIDE!!!!!!
 */

/* If you take this file as template for your module
 * you must re-implement every function.
 */

#define PY_TUPLE_NEW(n) \
	if (!(pArgs = PyTuple_New(n))) { \
        errno = ENOMEM; \
        return -1; \
    }

#define PY_ADD_TO_TUPLE(value, converter, pos) \
	if (!(pValue = converter (value))) { \
		Py_DECREF(pArgs); \
		errno = ENOMEM; \
        return -1; \
	} \
	PyTuple_SetItem(pArgs, pos, pValue);

#define PY_CALL_WITH_ARGS(func) \
	pRet = PyObject_CallObject(pf->pFunc##func, pArgs); \
	Py_DECREF(pArgs); \
	if (!pRet) { \
        errno = E_INTERNAL; \
        return -1; \
    }

struct my_dir {
    long			offset; 
    long			entries; 
    struct dirent	entry[1];
};

struct pyfuncs {
    PyObject	*pModule;
    PyObject	*pFuncConnect;
    PyObject	*pFuncStat;
    PyObject	*pFuncFStat;
    PyObject	*pFuncGetDir;
    PyObject	*pFuncOpenFile;
    PyObject	*pFuncClose;
    PyObject	*pFuncUnlink;
    PyObject	*pFuncRead;
    PyObject	*pFuncPRead;
    PyObject	*pFuncWrite;
    PyObject	*pFuncPWrite;
    PyObject	*pFuncLSeek;
	char		cwd[255]; // MAXPATH?
};

static void free_python_data(void **data)
{
    SAFE_FREE(*data);
}

static int python_connect(vfs_handle_struct *handle,  const char *service, const char *user)    
{
	PyObject *pName, *pArgs, *pValue;
    const char *pysource;
    struct pyfuncs *pf;

    pf = SMB_MALLOC_P(struct pyfuncs);
    if (!pf) {
        errno = ENOMEM;
        return -1;
    }
    handle->data = (void *)pf;
    handle->free_data = free_python_data;

    memset(pf, 0, sizeof(*pf));
	pf->cwd[0] = '/';

    pysource = lp_parm_const_string(SNUM(handle->conn), "vfs_python", "module_name", NULL);
    if (pysource == NULL) {
		fprintf(stderr, "vfs_python:module_name not set!\n");
        errno = E_INTERNAL;
		return -1;
    }

	pName = PyString_FromString(pysource);
	pf->pModule = PyImport_Import(pName);
	Py_DECREF(pName);

	if (!pf->pModule) {
		fprintf(stderr, "Failed to load module '%s', make sure %s.py exists in a directory in the PYTHONPATH environment variable.\n", pysource, pysource);
		PyErr_Print();
        errno = E_INTERNAL;
		return -1;
	}

#define VFS_PY_REQUIRED_MODULE_FUNC(_member, _name) \
	pf->pFunc##_member = PyObject_GetAttrString(pf->pModule, _name); \
	if (!pf->pFunc##_member || !PyCallable_Check(pf->pFunc##_member)) { \
        if (pf->pFunc##_member) Py_DECREF(pf->pFunc##_member); \
		fprintf(stderr, "%s function not found or not callable\n", _name); \
        errno = E_INTERNAL; \
		return -1; \
	}

#define VFS_PY_OPTIONAL_MODULE_FUNC(_member, _name) \
	pf->pFunc##_member = PyObject_GetAttrString(pf->pModule, _name); \
    if (!pf->pFunc##_member) { \
        pf->pFunc##_member = NULL; \
        PyErr_Clear(); \
    } \
	else if (!PyCallable_Check(pf->pFunc##_member)) { \
        Py_DECREF(pf->pFunc##_member); \
		pf->pFunc##_member = NULL; \
	}

    VFS_PY_OPTIONAL_MODULE_FUNC(Connect, "connect");
    VFS_PY_REQUIRED_MODULE_FUNC(Stat, "getattr");
    VFS_PY_REQUIRED_MODULE_FUNC(FStat, "fstat");
    VFS_PY_REQUIRED_MODULE_FUNC(GetDir, "getdir");
    VFS_PY_REQUIRED_MODULE_FUNC(OpenFile, "open");
    VFS_PY_REQUIRED_MODULE_FUNC(Unlink, "unlink");
    VFS_PY_REQUIRED_MODULE_FUNC(Close, "close");
    VFS_PY_REQUIRED_MODULE_FUNC(Read, "read");
    VFS_PY_OPTIONAL_MODULE_FUNC(PRead, "pread");
    VFS_PY_REQUIRED_MODULE_FUNC(Write, "write");
    VFS_PY_OPTIONAL_MODULE_FUNC(PWrite, "pwrite");
    VFS_PY_REQUIRED_MODULE_FUNC(LSeek, "lseek");

    /* Load some functions
	pf->pFuncConnect = PyObject_GetAttrString(pf->pModule, "connect");
	if (!pf->pFuncConnect || !PyCallable_Check(pf->pFuncConnect)) {
		fprintf(stderr, "connect function not found or not callable\n");
        errno = ENOSYS;
		return -1;
	}*/

    // Init done, do connect
    if (pf->pFuncConnect) {
		pArgs = PyTuple_New(2);
		if (!pArgs) {
			errno = E_INTERNAL;
			return -1;
		}
	
		if (!(pValue = PyString_FromString(service))) {
			Py_DECREF(pArgs);
			errno = E_INTERNAL;
			return -1;
		}
		PyTuple_SetItem(pArgs, 0, pValue);
	
		if (!(pValue = PyString_FromString(user))) {
			Py_DECREF(pArgs);
			errno = E_INTERNAL;
			return -1;
		}
		PyTuple_SetItem(pArgs, 1, pValue);
	
		pValue = PyObject_CallObject(pf->pFuncConnect, pArgs);
		Py_DECREF(pArgs);
	
		if (pValue) {
			Py_DECREF(pValue);
			return (int) PyInt_AS_LONG(pValue);
		}
		fprintf(stderr, "vfs_python: connect() failed\n");
		PyErr_Print();
		errno = E_INTERNAL;
		return -1;
    }
    return 0;
}

static void python_disconnect(vfs_handle_struct *handle)
{
	;
}

static uint64_t python_disk_free(vfs_handle_struct *handle,  const char *path,
	bool small_query, uint64_t *bsize,
	uint64_t *dfree, uint64_t *dsize)
{
	*bsize = 100;
	*dfree = 10;
	*dsize = 100;
	return 10;
}

static int python_get_quota(vfs_handle_struct *handle,  enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dq)
{
	errno = ENOSYS;
	return -1;
}

static int python_set_quota(vfs_handle_struct *handle,  enum SMB_QUOTA_TYPE qtype, unid_t id, SMB_DISK_QUOTA *dq)
{
	errno = ENOSYS;
	return -1;
}

static int python_get_shadow_copy_data(vfs_handle_struct *handle, files_struct *fsp, struct shadow_copy_data *shadow_copy_data, bool labels)
{
	errno = ENOSYS;
	return -1;
}

static int python_statvfs(struct vfs_handle_struct *handle, const char *path, struct vfs_statvfs_struct *statbuf)
{
	errno = ENOSYS;
	return -1;
}

static uint32_t python_fs_capabilities(struct vfs_handle_struct *handle, enum timestamp_set_resolution *p_ts_res)
{
	return 0;
}

static NTSTATUS python_get_dfs_referrals(struct vfs_handle_struct *handle,
				       struct dfs_GetDFSReferral *r)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static DIR *python_opendir(vfs_handle_struct *handle,  const char *fname, const char *mask, uint32 attr)
{
    struct my_dir		*de;
	long				entries, i;
	struct pyfuncs		*pf = handle->data;
    PyObject			*pArgs, *pRet, *pValue;

	pArgs = PyTuple_New(1);
	if (!pArgs) {
		errno = E_INTERNAL;
		return NULL;
	}

	if (!(pValue = PyString_FromString(fname))) {
		Py_DECREF(pArgs);
		errno = E_INTERNAL;
		return NULL;
	}
	PyTuple_SetItem(pArgs, 0, pValue);

	pRet = PyObject_CallObject(pf->pFuncGetDir, pArgs);
	Py_DECREF(pArgs);

	if (!pRet) {
		fprintf(stderr, "vfs_python: getdir() failed\n");
		PyErr_Print();
		errno = ENOSYS;
		return NULL;
	}

	if (!PySequence_Check(pRet)) {
		fprintf(stderr, "getdir did not return a sequence object!\n");
		errno = E_INTERNAL;
		return NULL;
	}

	entries = PySequence_Length(pRet);
    if (NULL == (de = SMB_MALLOC(
		/* Could subtract the size of one entry from the malloc but that's okay */
		sizeof(*de) + (sizeof(de->entry[0]) * (entries - 1))
	))) {
	    Py_DECREF(pRet);
        errno = ENOMEM;
        return NULL;
    }
    de->offset = 0;
    de->entries = entries;

	for (i = 0; i < entries; i++) {
		memset(&de->entry[i], 0, sizeof(de->entry[0]));
		de->entry[i].d_ino = 1;
		pArgs = PySequence_GetItem(pRet, i);
		if (!pArgs) {
			Py_DECREF(pRet);
			SAFE_FREE(de);
			errno = E_INTERNAL;
			return NULL;
		}
		strncpy(de->entry[i].d_name, PyString_AsString(pArgs), sizeof(de->entry[0].d_name));
		de->entry[i].d_name[sizeof(de->entry[0].d_name) - 1] = '\0';
		Py_DECREF(pArgs);
	}
	Py_DECREF(pRet);

	return de;
}

static DIR *python_fdopendir(vfs_handle_struct *handle, files_struct *fsp, const char *mask, uint32 attr)
{
fprintf(stderr, "fdopendir\n");
    errno = ENOSYS;
	return NULL;
}

static struct dirent *python_readdir(vfs_handle_struct *handle,
				       DIR *dirp,
				       SMB_STRUCT_STAT *sbuf)
{
	struct dirent *result;
	struct my_dir *d = dirp;

	if (d->offset >= d->entries) return NULL;
	result = &d->entry[d->offset++];

    /* Default Posix readdir() does not give us stat info.
     * Set to invalid to indicate we didn't return this info. */
    if (sbuf)
        SET_STAT_INVALID(*sbuf);

	return result;
}

static void python_seekdir(vfs_handle_struct *handle,  DIR *dirp, long offset)
{
	struct my_dir *d = dirp;
	if (offset < d->entries) d->offset = offset;
}

static long python_telldir(vfs_handle_struct *handle,  DIR *dirp)
{
	struct my_dir *d = dirp;
	return d->offset;
}

static void python_rewind_dir(vfs_handle_struct *handle, DIR *dirp)
{
	struct my_dir *d = dirp;
    d->offset = 0;
}

static int python_mkdir(vfs_handle_struct *handle,  const char *path, mode_t mode)
{
	errno = ENOSYS;
	return -1;
}

static int python_rmdir(vfs_handle_struct *handle,  const char *path)
{
	errno = ENOSYS;
	return -1;
}

static int python_closedir(vfs_handle_struct *handle,  DIR *dir)
{
    if (dir) SAFE_FREE(dir);
	return 0;
}

static void python_init_search_op(struct vfs_handle_struct *handle, DIR *dirp)
{
	;
}

static int python_open(vfs_handle_struct *handle, struct smb_filename *smb_fname,
		     files_struct *fsp, int flags, mode_t mode)
{
	struct pyfuncs *pf = handle->data;
    PyObject *pArgs, *pRet, *pValue;   
    int r;

    PY_TUPLE_NEW(4);
    PY_ADD_TO_TUPLE(handle->conn->cwd, PyString_FromString, 0);
    PY_ADD_TO_TUPLE(smb_fname->base_name, PyString_FromString, 1);
    PY_ADD_TO_TUPLE(flags, PyInt_FromLong, 2);
    PY_ADD_TO_TUPLE(mode, PyInt_FromLong, 3);
    PY_CALL_WITH_ARGS(OpenFile);

	if (PyInt_AS_LONG(pRet) < 0) {
		errno = -1 * PyInt_AS_LONG(pRet);
		Py_DECREF(pRet);
		return -1;
	}

    r = PyInt_AS_LONG(pRet);
    Py_DECREF(pRet);
    return r;
}

static NTSTATUS python_create_file(struct vfs_handle_struct *handle,
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
    return create_file_default(handle->conn, req, root_dir_fid, smb_fname,
                   access_mask, share_access,
                   create_disposition, create_options,
                   file_attributes, oplock_request,
                   allocation_size, private_flags,
                   sd, ea_list, result,
                   pinfo);

}

static int python_close_fn(vfs_handle_struct *handle, files_struct *fsp)
{
	struct pyfuncs *pf = handle->data;
    PyObject *pArgs, *pRet, *pValue;   

    PY_TUPLE_NEW(1);
    PY_ADD_TO_TUPLE(fsp->fh->fd, PyInt_FromSsize_t, 0);
    PY_CALL_WITH_ARGS(Close);

	if (PyInt_AS_LONG(pRet) < 0) {
		errno = -1 * PyInt_AS_LONG(pRet);
		Py_DECREF(pRet);
		return -1;
	}

    Py_DECREF(pRet);
    return 0;
}

static ssize_t python_vfs_read(vfs_handle_struct *handle, files_struct *fsp, void *data, size_t n)
{
	struct pyfuncs *pf = handle->data;
    PyObject *pArgs, *pRet, *pValue;   
    char *pydata;
    ssize_t s;

    PY_TUPLE_NEW(2);
    PY_ADD_TO_TUPLE(fsp->fh->fd, PyInt_FromSsize_t, 0);
    PY_ADD_TO_TUPLE(n, PyInt_FromSize_t, 1);
    PY_CALL_WITH_ARGS(Read);

    if (PyString_Check(pRet)) {
	    pydata = PyString_AsString(pRet);
	    if (pydata == NULL) {
            Py_DECREF(pRet);
	        errno = E_INTERNAL;
	        return -1;
	    }
	    s = PyString_Size(pRet);

    } else if (PyByteArray_Check(pRet)) {
	    pydata = PyByteArray_AsString(pRet);
	    if (pydata == NULL) {
            Py_DECREF(pRet);
	        errno = E_INTERNAL;
	        return -1;
	    }
	    s = PyByteArray_Size(pRet);

    } else {
        errno = PyInt_AsLong(pRet);
        Py_DECREF(pRet);
        return -1;
    }

    memcpy(data, pydata, s > n ? n : s);

    Py_DECREF(pRet);
	return s;
}

static off_t python_lseek(vfs_handle_struct *, files_struct *, off_t, int);
static ssize_t python_pread(vfs_handle_struct *handle, files_struct *fsp, void *data, size_t n, off_t offset)
{
	struct pyfuncs *pf = handle->data;
    PyObject *pArgs, *pRet, *pValue;   
    char *pydata;
    ssize_t s;

    if (!pf->pFuncPRead) {
        off_t original_pos;
        /*
         * Simulate pread with lseek and read (like the default implementation
         * does.
         */
        if ((original_pos = python_lseek(handle, fsp, 0, SEEK_CUR)) == -1) return -1;
        if (python_lseek(handle, fsp, offset, SEEK_SET) == -1) return -1;
        s = python_vfs_read(handle, fsp, data, n);
        if (python_lseek(handle, fsp, original_pos, SEEK_SET) == -1) return -1;
        return s;
    }

    PY_TUPLE_NEW(3);
    PY_ADD_TO_TUPLE(fsp->fh->fd, PyInt_FromSsize_t, 0);
    PY_ADD_TO_TUPLE(n, PyInt_FromSize_t, 1);
    PY_ADD_TO_TUPLE(offset, PyInt_FromSize_t, 2);
    PY_CALL_WITH_ARGS(PRead);

    if (PyString_Check(pRet)) {
	    pydata = PyString_AsString(pRet);
	    if (pydata == NULL) {
            Py_DECREF(pRet);
	        errno = E_INTERNAL;
	        return -1;
	    }
	    s = PyString_Size(pRet);

    } else if (PyByteArray_Check(pRet)) {
	    pydata = PyByteArray_AsString(pRet);
	    if (pydata == NULL) {
            Py_DECREF(pRet);
	        errno = E_INTERNAL;
	        return -1;
	    }
	    s = PyByteArray_Size(pRet);

    } else {
        errno = PyInt_AsLong(pRet);
        Py_DECREF(pRet);
        return -1;
    }

    memcpy(data, pydata, s > n ? n : s);

    Py_DECREF(pRet);
	return s;
}

static struct tevent_req *python_pread_send(struct vfs_handle_struct *handle,
					  TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct files_struct *fsp,
					  void *data, size_t n, off_t offset)
{
	return NULL;
}

static ssize_t python_pread_recv(struct tevent_req *req, int *err)
{
	*err = ENOSYS;
	return -1;
}

static ssize_t python_write(vfs_handle_struct *handle, files_struct *fsp, const void *data, size_t n)
{
	struct pyfuncs *pf = handle->data;
    PyObject *pArgs, *pRet, *pValue;   
    char *pydata;
    ssize_t s;

    PY_TUPLE_NEW(2);
    PY_ADD_TO_TUPLE(fsp->fh->fd, PyInt_FromSsize_t, 0);
	if (!(pValue = PyString_FromStringAndSize(data, n))) {
		Py_DECREF(pArgs);
		errno = E_INTERNAL;
		return NULL;
	}
	PyTuple_SetItem(pArgs, 1, pValue);
    PY_CALL_WITH_ARGS(Write);

    s = PyInt_AsSsize_t(pRet);

    Py_DECREF(pRet);
	return s;
}

static ssize_t python_pwrite(vfs_handle_struct *handle, files_struct *fsp, const void *data, size_t n, off_t offset)
{
	struct pyfuncs *pf = handle->data;
    PyObject *pArgs, *pRet, *pValue;   
    char *pydata;
    ssize_t s;

    if (!pf->pFuncPRead) {
        off_t original_pos;
        /*
         * Simulate pread with lseek and read (like the default implementation
         * does.
         */
        if ((original_pos = python_lseek(handle, fsp, 0, SEEK_CUR)) == -1) return -1;
        if (python_lseek(handle, fsp, offset, SEEK_SET) == -1) return -1;
        s = python_write(handle, fsp, data, n);
        if (python_lseek(handle, fsp, original_pos, SEEK_SET) == -1) return -1;
        return s;
    }

    PY_TUPLE_NEW(3);
    PY_ADD_TO_TUPLE(fsp->fh->fd, PyInt_FromSsize_t, 0);
	if (!(pValue = PyString_FromStringAndSize(data, n))) {
		Py_DECREF(pArgs);
		errno = E_INTERNAL;
		return NULL;
	}
	PyTuple_SetItem(pArgs, 1, pValue);
    PY_ADD_TO_TUPLE(offset, PyInt_FromSize_t, 2);
    PY_CALL_WITH_ARGS(PWrite);

    s = PyInt_AsSsize_t(pRet);

    Py_DECREF(pRet);
	return s;
}

static struct tevent_req *python_pwrite_send(struct vfs_handle_struct *handle,
					   TALLOC_CTX *mem_ctx,
					   struct tevent_context *ev,
					   struct files_struct *fsp,
					   const void *data,
					   size_t n, off_t offset)
{
	return NULL;
}

static ssize_t python_pwrite_recv(struct tevent_req *req, int *err)
{
	*err = ENOSYS;
	return -1;
}

static off_t python_lseek(vfs_handle_struct *handle, files_struct *fsp, off_t offset, int whence)
{
	struct pyfuncs *pf = handle->data;
    PyObject *pArgs, *pRet, *pValue;   
    off_t o;

    PY_TUPLE_NEW(3);
    PY_ADD_TO_TUPLE(fsp->fh->fd, PyInt_FromSsize_t, 0);
    PY_ADD_TO_TUPLE(offset, PyInt_FromSize_t, 1);
    PY_ADD_TO_TUPLE(whence, PyInt_FromSize_t, 2);
    PY_CALL_WITH_ARGS(LSeek);

    o = PyInt_AsSsize_t(pRet);

    Py_DECREF(pRet);
	return o;
}

static ssize_t python_sendfile(vfs_handle_struct *handle, int tofd, files_struct *fromfsp, const DATA_BLOB *hdr, off_t offset, size_t n)
{
	errno = ENOSYS;
	return -1;
}

static ssize_t python_recvfile(vfs_handle_struct *handle, int fromfd, files_struct *tofsp, off_t offset, size_t n)
{
	errno = ENOSYS;
	return -1;
}

static int python_rename(vfs_handle_struct *handle,
		       const struct smb_filename *smb_fname_src,
		       const struct smb_filename *smb_fname_dst)
{
	errno = ENOSYS;
	return -1;
}

static int python_fsync(vfs_handle_struct *handle, files_struct *fsp)
{
	errno = ENOSYS;
	return -1;
}

static struct tevent_req *python_fsync_send(struct vfs_handle_struct *handle,
					  TALLOC_CTX *mem_ctx,
					  struct tevent_context *ev,
					  struct files_struct *fsp)
{
	return NULL;
}

static int python_fsync_recv(struct tevent_req *req, int *err)
{
	*err = ENOSYS;
	return -1;
}

static int python_stat_helper(PyObject *pRet, SMB_STRUCT_STAT *st)
{
    PyObject *pValue;
/*
struct stat_ex {
    dev_t       st_ex_dev;
    ino_t       st_ex_ino;
    mode_t      st_ex_mode;
    nlink_t     st_ex_nlink;
    uid_t       st_ex_uid;
    gid_t       st_ex_gid;
    dev_t       st_ex_rdev;
    off_t       st_ex_size;
    struct timespec st_ex_atime;
    struct timespec st_ex_mtime;
    struct timespec st_ex_ctime;
    struct timespec st_ex_btime; // birthtime
    // Is birthtime real, or was it calculated ?
    bool        st_ex_calculated_birthtime;
    blksize_t   st_ex_blksize;
    blkcnt_t    st_ex_blocks;

    uint32_t    st_ex_flags;
    uint32_t    st_ex_mask;

    //
     * Add space for VFS internal extensions. The initial user of this
     * would be the onefs modules, passing the snapid from the stat calls
     * to the file_id_create call. Maybe we'll have to expand this later,
     * but the core of Samba should never look at this field.
     //
    uint64_t vfs_private;
};
*/

#define VFS_PY_STAT_VALUE(_name, _member, _default) \
	if ((pValue = PyMapping_GetItemString(pRet, _name))) { \
		st-> _member = PyInt_AsUnsignedLongLongMask(pValue); \
		Py_DECREF(pValue); \
	} else { \
		st-> _member = _default; \
	}

#define VFS_PY_STAT_TIMESPEC_VALUE(_name, _member) \
	do { \
		VFS_PY_STAT_VALUE(_name, _member .tv_sec, 0); \
		st-> _member .tv_nsec = 0; \
	} while(0);

#define VFS_PY_STAT_LONG(_name, _value) \
	do { \
		v = 0; \
		if ((pValue = PyMapping_GetItemString(pRet, _name))) { \
			_value = PyInt_AsUnsignedLongLongMask(pValue); \
			Py_DECREF(pValue); \
		} \
	} while(0);

	VFS_PY_STAT_VALUE("st_dev", st_ex_dev, 1);
	VFS_PY_STAT_VALUE("st_ino", st_ex_ino, 1);
	VFS_PY_STAT_VALUE("st_nlink", st_ex_nlink, 1);
	VFS_PY_STAT_VALUE("st_uid", st_ex_uid, 0);
	VFS_PY_STAT_VALUE("st_gid", st_ex_gid, 0);
	VFS_PY_STAT_VALUE("st_rdev", st_ex_gid, 1);
	VFS_PY_STAT_VALUE("st_size", st_ex_size, 0);
	VFS_PY_STAT_VALUE("st_blksize", st_ex_blksize, 512);
	VFS_PY_STAT_VALUE("st_mode", st_ex_mode, 0);

	if (PyMapping_HasKeyString(pRet, "st_blocks")) {
		VFS_PY_STAT_VALUE("st_blocks", st_ex_blocks, 0);
	} else {
		st->st_ex_blocks = st->st_ex_size / 512;
		if (st->st_ex_size % 512) st->st_ex_blocks++;
	}

	VFS_PY_STAT_TIMESPEC_VALUE("st_atime", st_ex_atime);
	VFS_PY_STAT_TIMESPEC_VALUE("st_mtime", st_ex_mtime);
	VFS_PY_STAT_TIMESPEC_VALUE("st_ctime", st_ex_ctime);
	if (PyMapping_HasKeyString(pRet, "st_btime")) {
		VFS_PY_STAT_TIMESPEC_VALUE("st_btime", st_ex_btime);
	} else {
		st->st_ex_btime.tv_sec = st->st_ex_ctime.tv_sec;
		st->st_ex_btime.tv_nsec = 0;
	}

	st->st_ex_flags = 0;
	st->st_ex_mask = 0;
	st->vfs_private = 0;
	st->st_ex_calculated_birthtime = 0;

	Py_DECREF(pRet);
	return 0;
}

static int python_stat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
	PyObject *pArgs, *pValue, *pRet;
	struct pyfuncs *pf = handle->data;

	/* We don't support streams (yet?) */
    if (smb_fname->stream_name) {
		errno = ENOENT;
		return -1;
    }

	pArgs = PyTuple_New(1);
	if (!pArgs) {
		errno = E_INTERNAL;
		return -1;
	}

	if (!(pValue = PyString_FromString(smb_fname->base_name))) {
		Py_DECREF(pArgs);
		errno = E_INTERNAL;
		return -1;
	}

	PyTuple_SetItem(pArgs, 0, pValue);

	pRet = PyObject_CallObject(pf->pFuncStat, pArgs);
	Py_DECREF(pArgs);

	if (!pRet) {
		fprintf(stderr, "vfs_python: getattr() failed.\n");
		PyErr_Print();
		errno = ENOSYS;
		return -1;
	}

	if (!PyMapping_Check(pRet)) {
		Py_DECREF(pRet);
		errno = ENOENT;
		return -1;
	}

    return python_stat_helper(pRet, &smb_fname->st);
}

static int python_fstat(vfs_handle_struct *handle, files_struct *fsp, SMB_STRUCT_STAT *sbuf)
{
	PyObject *pArgs, *pValue, *pRet;
	struct pyfuncs *pf = handle->data;

	pArgs = PyTuple_New(1);
	if (!pArgs) {
		errno = E_INTERNAL;
		return -1;
	}

	if (!(pValue = PyInt_FromSsize_t(fsp->fh->fd))) {
		Py_DECREF(pArgs);
		errno = E_INTERNAL;
		return -1;
	}

	PyTuple_SetItem(pArgs, 0, pValue);

	pRet = PyObject_CallObject(pf->pFuncFStat, pArgs);
	Py_DECREF(pArgs);

	if (!pRet) {
		fprintf(stderr, "vfs_python: fstat() failed.\n");
		PyErr_Print();
		errno = ENOSYS;
		return -1;
	}

	if (!PyMapping_Check(pRet)) {
		Py_DECREF(pRet);
		errno = ENOENT;
		return -1;
	}

    return python_stat_helper(pRet, sbuf);
}

static int python_lstat(vfs_handle_struct *handle, struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return -1;
}

static uint64_t python_get_alloc_size(struct vfs_handle_struct *handle, struct files_struct *fsp, const SMB_STRUCT_STAT *sbuf)
{
    if(S_ISDIR(sbuf->st_ex_mode)) {
        return 0;
    }

	return sbuf->st_ex_size;
}

static int python_unlink(vfs_handle_struct *handle,
		       const struct smb_filename *smb_fname)
{
	errno = ENOSYS;
	return -1;
}

static int python_chmod(vfs_handle_struct *handle,  const char *path, mode_t mode)
{
	errno = ENOSYS;
	return -1;
}

static int python_fchmod(vfs_handle_struct *handle, files_struct *fsp, mode_t mode)
{
	errno = ENOSYS;
	return -1;
}

static int python_chown(vfs_handle_struct *handle,  const char *path, uid_t uid, gid_t gid)
{
	errno = ENOSYS;
	return -1;
}

static int python_fchown(vfs_handle_struct *handle, files_struct *fsp, uid_t uid, gid_t gid)
{
	errno = ENOSYS;
	return -1;
}

static int python_lchown(vfs_handle_struct *handle,  const char *path, uid_t uid, gid_t gid)
{
	errno = ENOSYS;
	return -1;
}

static int python_chdir(vfs_handle_struct *handle,  const char *path)
{
	struct pyfuncs *pf = handle->data;
	struct smb_filename fn;
	int r;
	memset(&fn, 0, sizeof(fn));

	fn.base_name = (char *) path;
	r = python_stat(handle, &fn);

	if (r == 0) {
		strncpy(&pf->cwd[0], path, sizeof(pf->cwd[0]));
		pf->cwd[sizeof(pf->cwd) - 1] = '\0';
	}
	return r;
}

/* Must return a pointer to memory that can be deallocated with SAFE_FREE() */
static char *python_getwd(vfs_handle_struct *handle)
{
	struct pyfuncs *pf = handle->data;
	int bufsz = strlen(pf->cwd) + 1;
	char *r = SMB_MALLOC(bufsz);
	if (r) strncpy(r, pf->cwd, bufsz);
	return r;
}

static int python_ntimes(vfs_handle_struct *handle,
		       const struct smb_filename *smb_fname,
		       struct smb_file_time *ft)
{
	errno = ENOSYS;
	return -1;
}

static int python_ftruncate(vfs_handle_struct *handle, files_struct *fsp, off_t offset)
{
	errno = ENOSYS;
	return -1;
}

static int python_fallocate(vfs_handle_struct *handle, files_struct *fsp,
			enum vfs_fallocate_mode mode,
			off_t offset, off_t len)
{
	errno = ENOSYS;
	return -1;
}

static bool python_lock(vfs_handle_struct *handle, files_struct *fsp, int op, off_t offset, off_t count, int type)
{
	errno = ENOSYS;
	return false;
}

static int python_kernel_flock(struct vfs_handle_struct *handle, struct files_struct *fsp, uint32 share_mode, uint32 access_mask)
{
    return 0;
// XXX
	errno = ENOSYS;
	return -1;
}

static int python_linux_setlease(struct vfs_handle_struct *handle, struct files_struct *fsp, int leasetype)
{
	errno = ENOSYS;
	return -1;
}

static bool python_getlock(vfs_handle_struct *handle, files_struct *fsp, off_t *poffset, off_t *pcount, int *ptype, pid_t *ppid)
{
	errno = ENOSYS;
	return false;
}

static int python_symlink(vfs_handle_struct *handle,  const char *oldpath, const char *newpath)
{
	errno = ENOSYS;
	return -1;
}

static int python_vfs_readlink(vfs_handle_struct *handle, const char *path, char *buf, size_t bufsiz)
{
	errno = ENOSYS;
	return -1;
}

static int python_link(vfs_handle_struct *handle,  const char *oldpath, const char *newpath)
{
	errno = ENOSYS;
	return -1;
}

static int python_mknod(vfs_handle_struct *handle,  const char *path, mode_t mode, SMB_DEV_T dev)
{
	errno = ENOSYS;
	return -1;
}

static char *python_realpath(vfs_handle_struct *handle,  const char *path)
{
#define FAKE_REALPATH "/"
    char *p;
	int offset = 0;
	int bufsz = sizeof(FAKE_REALPATH) + strlen(path); 

    p = SMB_MALLOC(bufsz);
	if (!p) {
		errno = ENOMEM;
		return NULL;
	}
    strncpy(p, FAKE_REALPATH, bufsz);

	if (strcmp(path, ".") == 0) return p;

	if (path[0] == '/') offset = 1;

    strncpy(p + sizeof(FAKE_REALPATH) - 1, path + offset, bufsz - sizeof(FAKE_REALPATH) - 1);
	p[bufsz - 1] = '\0';
	return p;
}

static NTSTATUS python_notify_watch(struct vfs_handle_struct *handle,
	    struct sys_notify_context *ctx,
	    const char *path,
	    uint32_t *filter,
	    uint32_t *subdir_filter,
	    void (*callback)(struct sys_notify_context *ctx, void *private_data, struct notify_event *ev),
	    void *private_data, void *handle_p)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static int python_chflags(vfs_handle_struct *handle,  const char *path, uint flags)
{
	errno = ENOSYS;
	return -1;
}

static struct file_id python_file_id_create(vfs_handle_struct *handle,
					  const SMB_STRUCT_STAT *sbuf)
{
	struct file_id id;
	ZERO_STRUCT(id);

    id.devid = sbuf->st_ex_dev;
    id.inode = sbuf->st_ex_ino;

	return id;
}

static NTSTATUS python_streaminfo(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				const char *fname,
				TALLOC_CTX *mem_ctx,
				unsigned int *num_streams,
				struct stream_struct **streams)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static int python_get_real_filename(struct vfs_handle_struct *handle,
				const char *path,
				const char *name,
				TALLOC_CTX *mem_ctx,
				char **found_name)
{
	errno = ENOSYS;
	return -1;
}

static const char *python_connectpath(struct vfs_handle_struct *handle,
				const char *filename)
{
	return handle->conn->connectpath;
}

static NTSTATUS python_brl_lock_windows(struct vfs_handle_struct *handle,
				struct byte_range_lock *br_lck,
				struct lock_struct *plock,
				bool blocking_lock,
				struct blocking_lock_record *blr)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static bool python_brl_unlock_windows(struct vfs_handle_struct *handle,
				struct messaging_context *msg_ctx,
				struct byte_range_lock *br_lck,
				const struct lock_struct *plock)
{
	errno = ENOSYS;
	return false;
}

static bool python_brl_cancel_windows(struct vfs_handle_struct *handle,
				struct byte_range_lock *br_lck,
				struct lock_struct *plock,
				struct blocking_lock_record *blr)
{
	errno = ENOSYS;
	return false;
}

static bool python_strict_lock(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				struct lock_struct *plock)
{
	errno = ENOSYS;
	return false;
}

static void python_strict_unlock(struct vfs_handle_struct *handle,
				struct files_struct *fsp,
				struct lock_struct *plock)
{
	;
}

static NTSTATUS python_translate_name(struct vfs_handle_struct *handle,
				const char *mapped_name,
				enum vfs_translate_direction direction,
				TALLOC_CTX *mem_ctx,
				char **pmapped_name)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS python_fsctl(struct vfs_handle_struct *handle,
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
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS python_fget_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
				 uint32 security_info,
				 TALLOC_CTX *mem_ctx,
				 struct security_descriptor **ppdesc)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS python_get_nt_acl(vfs_handle_struct *handle,
				const char *name, uint32 security_info,
				TALLOC_CTX *mem_ctx,
				struct security_descriptor **ppdesc)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static NTSTATUS python_fset_nt_acl(vfs_handle_struct *handle, files_struct *fsp,
	uint32 security_info_sent, const struct security_descriptor *psd)
{
	return NT_STATUS_NOT_IMPLEMENTED;
}

static int python_chmod_acl(vfs_handle_struct *handle,  const char *name, mode_t mode)
{
	errno = ENOSYS;
	return -1;
}

static int python_fchmod_acl(vfs_handle_struct *handle, files_struct *fsp, mode_t mode)
{
	errno = ENOSYS;
	return -1;
}

static SMB_ACL_T python_sys_acl_get_file(vfs_handle_struct *handle,
				       const char *path_p,
				       SMB_ACL_TYPE_T type,
				       TALLOC_CTX *mem_ctx)
{
	errno = ENOSYS;
	return (SMB_ACL_T)NULL;
}

static SMB_ACL_T python_sys_acl_get_fd(vfs_handle_struct *handle,
				     files_struct *fsp,
				     TALLOC_CTX *mem_ctx)
{
	errno = ENOSYS;
	return (SMB_ACL_T)NULL;
}

static int python_sys_acl_blob_get_file(vfs_handle_struct *handle,  const char *path_p, TALLOC_CTX *mem_ctx, char **blob_description, DATA_BLOB *blob)
{
	errno = ENOSYS;
	return -1;
}

static int python_sys_acl_blob_get_fd(vfs_handle_struct *handle, files_struct *fsp, TALLOC_CTX *mem_ctx, char **blob_description, DATA_BLOB *blob)
{
	errno = ENOSYS;
	return -1;
}

static int python_sys_acl_set_file(vfs_handle_struct *handle,  const char *name, SMB_ACL_TYPE_T acltype, SMB_ACL_T theacl)
{
	errno = ENOSYS;
	return -1;
}

static int python_sys_acl_set_fd(vfs_handle_struct *handle, files_struct *fsp, SMB_ACL_T theacl)
{
	errno = ENOSYS;
	return -1;
}

static int python_sys_acl_delete_def_file(vfs_handle_struct *handle,  const char *path)
{
	errno = ENOSYS;
	return -1;
}

static ssize_t python_getxattr(vfs_handle_struct *handle, const char *path, const char *name, void *value, size_t size)
{
	errno = ENOSYS;
	return -1;
}

static ssize_t python_fgetxattr(vfs_handle_struct *handle, struct files_struct *fsp, const char *name, void *value, size_t size)
{
	errno = ENOSYS;
	return -1;
}

static ssize_t python_listxattr(vfs_handle_struct *handle, const char *path, char *list, size_t size)
{
	errno = ENOSYS;
	return -1;
}

static ssize_t python_flistxattr(vfs_handle_struct *handle, struct files_struct *fsp, char *list, size_t size)
{
	errno = ENOSYS;
	return -1;
}

static int python_removexattr(vfs_handle_struct *handle, const char *path, const char *name)
{
	errno = ENOSYS;
	return -1;
}

static int python_fremovexattr(vfs_handle_struct *handle, struct files_struct *fsp, const char *name)
{
	errno = ENOSYS;
	return -1;
        return SMB_VFS_NEXT_FREMOVEXATTR(handle, fsp, name);
}

static int python_setxattr(vfs_handle_struct *handle, const char *path, const char *name, const void *value, size_t size, int flags)
{
	errno = ENOSYS;
	return -1;
}

static int python_fsetxattr(vfs_handle_struct *handle, struct files_struct *fsp, const char *name, const void *value, size_t size, int flags)
{
	errno = ENOSYS;
	return -1;
}

static bool python_aio_force(struct vfs_handle_struct *handle, struct files_struct *fsp)
{
	errno = ENOSYS;
	return false;
}

static bool python_is_offline(struct vfs_handle_struct *handle, const struct smb_filename *fname, SMB_STRUCT_STAT *sbuf)
{
	errno = ENOSYS;
	return false;
}

static int python_set_offline(struct vfs_handle_struct *handle, const struct smb_filename *fname)
{
	errno = ENOSYS;
	return -1;
}

/* VFS operations structure */

struct vfs_fn_pointers python_opaque_fns = {
	/* Disk operations */

	.connect_fn = python_connect,
	.disconnect_fn = python_disconnect,
	.disk_free_fn = python_disk_free,
	.get_quota_fn = python_get_quota,
	.set_quota_fn = python_set_quota,
	.get_shadow_copy_data_fn = python_get_shadow_copy_data,
	.statvfs_fn = python_statvfs,
	.fs_capabilities_fn = python_fs_capabilities,
	.get_dfs_referrals_fn = python_get_dfs_referrals,

	/* Directory operations */

	.opendir_fn = python_opendir,
	.fdopendir_fn = python_fdopendir,
	.readdir_fn = python_readdir,
	.seekdir_fn = python_seekdir,
	.telldir_fn = python_telldir,
	.rewind_dir_fn = python_rewind_dir,
	.mkdir_fn = python_mkdir,
	.rmdir_fn = python_rmdir,
	.closedir_fn = python_closedir,
	.init_search_op_fn = python_init_search_op,

	/* File operations */

	.open_fn = python_open,
	//.create_file_fn = python_create_file,
	.close_fn = python_close_fn,
	.read_fn = python_vfs_read,
	.pread_fn = python_pread,
	.pread_send_fn = python_pread_send,
	.pread_recv_fn = python_pread_recv,
	.write_fn = python_write,
	.pwrite_fn = python_pwrite,
	.pwrite_send_fn = python_pwrite_send,
	.pwrite_recv_fn = python_pwrite_recv,
	.lseek_fn = python_lseek,
	.sendfile_fn = python_sendfile,
	.recvfile_fn = python_recvfile,
	.rename_fn = python_rename,
	.fsync_fn = python_fsync,
	.fsync_send_fn = python_fsync_send,
	.fsync_recv_fn = python_fsync_recv,
	.stat_fn = python_stat,
	.fstat_fn = python_fstat,
	.lstat_fn = python_lstat,
	.get_alloc_size_fn = python_get_alloc_size,
	.unlink_fn = python_unlink,
	.chmod_fn = python_chmod,
	.fchmod_fn = python_fchmod,
	.chown_fn = python_chown,
	.fchown_fn = python_fchown,
	.lchown_fn = python_lchown,
	//.chdir_fn = python_chdir,
	//.getwd_fn = python_getwd,
	.ntimes_fn = python_ntimes,
	.ftruncate_fn = python_ftruncate,
	.fallocate_fn = python_fallocate,
	.lock_fn = python_lock,
	.kernel_flock_fn = python_kernel_flock,
	.linux_setlease_fn = python_linux_setlease,
	.getlock_fn = python_getlock,
	.symlink_fn = python_symlink,
	.readlink_fn = python_vfs_readlink,
	.link_fn = python_link,
	.mknod_fn = python_mknod,
	//.realpath_fn = python_realpath,
	.notify_watch_fn = python_notify_watch,
	.chflags_fn = python_chflags,
	.file_id_create_fn = python_file_id_create,

	.streaminfo_fn = python_streaminfo,
/*
	.get_real_filename_fn = python_get_real_filename,
	.connectpath_fn = python_connectpath,
	.brl_lock_windows_fn = python_brl_lock_windows,
	.brl_unlock_windows_fn = python_brl_unlock_windows,
	.brl_cancel_windows_fn = python_brl_cancel_windows,
	.strict_lock_fn = python_strict_lock,
	.strict_unlock_fn = python_strict_unlock,
	.translate_name_fn = python_translate_name,
*/
	.fsctl_fn = python_fsctl,

	/* NT ACL operations. */
/*
	.fget_nt_acl_fn = python_fget_nt_acl,
	.get_nt_acl_fn = python_get_nt_acl,
	.fset_nt_acl_fn = python_fset_nt_acl,
*/
	/* POSIX ACL operations. */

	.chmod_acl_fn = python_chmod_acl,
	.fchmod_acl_fn = python_fchmod_acl,
/*
	.sys_acl_get_file_fn = python_sys_acl_get_file,
	.sys_acl_get_fd_fn = python_sys_acl_get_fd,
	.sys_acl_blob_get_file_fn = python_sys_acl_blob_get_file,
	.sys_acl_blob_get_fd_fn = python_sys_acl_blob_get_fd,
	.sys_acl_set_file_fn = python_sys_acl_set_file,
	.sys_acl_set_fd_fn = python_sys_acl_set_fd,
	.sys_acl_delete_def_file_fn = python_sys_acl_delete_def_file,
*/

	/* EA operations. */
	.getxattr_fn = python_getxattr,
	.fgetxattr_fn = python_fgetxattr,
	.listxattr_fn = python_listxattr,
	.flistxattr_fn = python_flistxattr,
	.removexattr_fn = python_removexattr,
	.fremovexattr_fn = python_fremovexattr,
	.setxattr_fn = python_setxattr,
	.fsetxattr_fn = python_fsetxattr,

	/* aio operations */
	.aio_force_fn = python_aio_force,

	/* offline operations */
	.is_offline_fn = python_is_offline,
	.set_offline_fn = python_set_offline
};

NTSTATUS vfs_python_init(void)
{
	Py_Initialize();
	return smb_register_vfs(SMB_VFS_INTERFACE_VERSION, "python", &python_opaque_fns);
}
