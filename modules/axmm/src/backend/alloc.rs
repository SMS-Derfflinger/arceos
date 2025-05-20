use axalloc::global_allocator;
use axhal::mem::{phys_to_virt, virt_to_phys};
use axhal::paging::{MappingFlags, PageSize, PageTable};
use memory_addr::{PageIter, PageIter4K, PhysAddr, VirtAddr, PAGE_SIZE_4K};

use super::{Backend, HUGE_PAGE_SIZE_2M};
pub type PageIter2M<A> = PageIter<HUGE_PAGE_SIZE_2M, A>;

fn alloc_frame(zeroed: bool, size: usize) -> Option<PhysAddr> {
    let vaddr = VirtAddr::from(global_allocator().alloc_pages(size / PAGE_SIZE_4K, size).ok()?);
    if zeroed {
        unsafe { core::ptr::write_bytes(vaddr.as_mut_ptr(), 0, size) };
    }
    let paddr = virt_to_phys(vaddr);
    Some(paddr)
}

fn dealloc_frame(frame: PhysAddr, size: usize) {
    let vaddr = phys_to_virt(frame);
    global_allocator().dealloc_pages(vaddr.as_usize(), size / PAGE_SIZE_4K);
}

impl Backend {
    /// Creates a new allocation mapping backend.
    pub const fn new_alloc(populate: bool) -> Self {
        Self::Alloc { populate }
    }

    /// temporarily support 2M huge page only.
    pub(crate) fn map_alloc(
        start: VirtAddr,
        size: usize,
        flags: MappingFlags,
        pt: &mut PageTable,
        populate: bool,
        page_size: PageSize,
    ) -> bool {
        debug!(
            "map_alloc: [{:#x}, {:#x}) {:?} (populate={})",
            start,
            start + size,
            flags,
            populate
        );
        if populate {
            match page_size {
                PageSize::Size4K => {
                    // allocate all possible physical frames for populated mapping.
                    for addr in PageIter4K::new(start, start + size).unwrap() {
                        if let Some(frame) = alloc_frame(true, PAGE_SIZE_4K) {
                            if let Ok(tlb) = pt.map(addr, frame, page_size, flags) {
                                tlb.ignore(); // TLB flush on map is unnecessary, as there are no outdated mappings.
                            } else {
                                return false;
                            }
                        }
                    }
                },
                PageSize::Size2M => {
                    for addr in PageIter2M::new(start, start + size).unwrap() {
                        if let Some(frame) = alloc_frame(true, HUGE_PAGE_SIZE_2M) {
                            if let Ok(tlb) = pt.map(addr, frame, page_size, flags) {
                                tlb.ignore(); // TLB flush on map is unnecessary, as there are no outdated mappings.
                            } else {
                                return false;
                            }
                        }
                    }
                },
                _ => return false,
            }
        } else {
            // create mapping entries on demand later in `handle_page_fault_alloc`.
        }
        true
    }

    pub(crate) fn unmap_alloc(
        start: VirtAddr,
        size: usize,
        pt: &mut PageTable,
        _populate: bool,
        page_size: PageSize,
    ) -> bool {
        debug!("unmap_alloc: [{:#x}, {:#x})", start, start + size);
        match page_size {
            PageSize::Size4K => {
                for addr in PageIter4K::new(start, start + size).unwrap() {
                    if let Ok((frame, page_size, tlb)) = pt.unmap(addr) {
                        // Deallocate the physical frame if there is a mapping in the
                        // page table.
                        if page_size.is_huge() {
                            return false;
                        }
                        tlb.flush();
                        dealloc_frame(frame, PAGE_SIZE_4K);
                    } else {
                        // Deallocation is needn't if the page is not mapped.
                    }
                }
            },
            PageSize::Size2M => {
                for addr in PageIter2M::new(start, start + size).unwrap() {
                    if let Ok((frame, _page_size, tlb)) = pt.unmap(addr) {
                        tlb.flush();
                        dealloc_frame(frame, HUGE_PAGE_SIZE_2M);
                    } else {
                        // Deallocation is needn't if the page is not mapped.
                    }
                }
            },
            _ => return false,
        }
        true
    }

    pub(crate) fn handle_page_fault_alloc(
        vaddr: VirtAddr,
        orig_flags: MappingFlags,
        pt: &mut PageTable,
        populate: bool,
    ) -> bool {
        if populate {
            false // Populated mappings should not trigger page faults.
        } else if let Some(frame) = alloc_frame(true, PAGE_SIZE_4K) {
            // Allocate a physical frame lazily and map it to the fault address.
            // `vaddr` does not need to be aligned. It will be automatically
            // aligned during `pt.map` regardless of the page size.
            pt.map(vaddr, frame, PageSize::Size4K, orig_flags)
                .map(|tlb| tlb.flush())
                .is_ok()
        } else {
            false
        }
    }
}
