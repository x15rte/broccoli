//! Owned heap storage for Win32 structures.
//!
//! The Windows enumeration and token APIs (`GetAdaptersAddresses`,
//! `GetExtendedTcpTable`, `GetTokenInformation`) write structs containing
//! pointer and 64-bit fields into a caller-supplied buffer. A `Vec<u8>`
//! promises 1-byte alignment, and the system allocator's over-alignment is not
//! a language guarantee, so a pointer into it cannot be cast to those structs.
//! [`AlignedBuffer`] is the one owner of that rule: it allocates zeroed bytes
//! with the struct's own `align_of`, records the layout, and frees it with the
//! same layout, so a cast of its base pointer to `T` is sound.

use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::marker::PhantomData;
use std::mem::align_of;
use std::ptr::NonNull;

/// A zeroed heap allocation whose base address is aligned for `T`.
pub(crate) struct AlignedBuffer<T> {
    ptr: NonNull<u8>,
    layout: Layout,
    _element: PhantomData<T>,
}

impl<T> AlignedBuffer<T> {
    /// Allocate `size` zeroed bytes aligned for `T`. `None` on a zero size, an
    /// unrepresentable layout, or allocation failure — callers treat every one
    /// as a best-effort read failure.
    pub(crate) fn zeroed(size: usize) -> Option<Self> {
        if size == 0 {
            return None;
        }
        let layout = Layout::from_size_align(size, align_of::<T>()).ok()?;
        // SAFETY: `layout` has a non-zero size (checked above) and a
        // power-of-two alignment, so `alloc_zeroed` returns a pointer valid
        // for `layout.size()` bytes of zeroed memory with `layout.align()`,
        // or null on allocation failure (converted to `None` below).
        let ptr = unsafe { alloc_zeroed(layout) };
        Some(Self {
            ptr: NonNull::new(ptr)?,
            layout,
            _element: PhantomData,
        })
    }

    /// The buffer's base pointer, aligned for the `T` this buffer was
    /// allocated for.
    pub(crate) fn as_mut_ptr(&self) -> *mut T {
        self.ptr.as_ptr().cast()
    }

    /// The allocation's size in bytes.
    pub(crate) fn size(&self) -> usize {
        self.layout.size()
    }
}

impl<T> Drop for AlignedBuffer<T> {
    fn drop(&mut self) {
        // SAFETY: `ptr` was returned by `alloc_zeroed` with exactly this
        // `layout` (stored verbatim at allocation time); it is non-null and
        // has not been freed or reallocated, so the dealloc matches.
        unsafe { dealloc(self.ptr.as_ptr(), self.layout) }
    }
}
