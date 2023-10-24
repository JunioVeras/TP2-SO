/**
 * @file pager.c
 * @author
 * @authors Vinícius Braga Freire (vinicius.braga@dcc.ufmg.br), Júnio Veras de
 * Jesus Lima (junio.veras@dcc.ufmg.br)
 * @brief
 * @version 0.1
 * @date 2023-05-11
 *
 * @copyright Copyright (c) 2023
 *
 */

#include "pager.h"
#include <assert.h>
#include <stdlib.h>
#include "errno.h"
#include "mmu.h"
#include "pthread.h"
#include "stdio.h"
#include "sys/mman.h"
#include "unistd.h"

// ====================== DLIST ================================================

typedef struct dlist {
    struct dnode* head;
    struct dnode* tail;
    int count;
} dlist;

typedef struct dnode {
    struct dnode* prev;
    struct dnode* next;
    void* data;
} dnode;

typedef void (*dlist_data_func)(void* data);
typedef int (*dlist_cmp_func)(const void* e1, const void* e2, void* userdata);

struct dlist* dlist_create(void);
void* dlist_push_right(struct dlist* dl, void* data);
/* remove the node from the list in O(1) */
void dlist_remove_from_node(struct dlist* dl, struct dnode* node);

// ====================== PAGER ================================================

/**
 * @brief Structure to represent a physical memory frame.
 *
 */
typedef struct frame {
    /**
     * @brief Sinalize which process is using this frame. Then `-1` indicates
     * that is a free slot of memory and anything else is the process ID that is
     * using it.
     *
     */
    pid_t pid;
    /**
     * @brief Flag used in second chance algorithm.
     *
     */
    u_int8_t flag;
    /**
     * @brief Used to map back to which page this frame is beign referenced
     * from.
     *
     */
    int pageID;
} frame_t;

/**
 * @brief Structure to represent a backing disk block.
 *
 */
typedef struct block {
    /**
     * @brief Sinalize which process is using this block. Then `-1` indicates
     * that is a free backing block and anything else is the process ID that is
     * using it.
     *
     */
    pid_t pid;
} block_t;

/**
 * @brief Structure that represents a virtual memory page.
 *
 */
typedef struct page {
    /**
     * @brief Indicates the frame ID used by this page. This is responsible for
     * the virtual address translation. If this ID is `-1`, then this page is
     * not resident in the memory.
     *
     */
    int frameID;
    /**
     * @brief Indicates the block ID that is going to store this page in the
     * disk when this page is removed from memory.
     *
     */
    int blockID;
    /**
     * @brief Mask of flags used to represent the control bits of a page
     * address. The first bit indicates whether this page has ever been
     * initialized and the second bit if this page has ever been writen in this
     * stay at the current frame.
     *
     */
    u_int8_t flag_mask;
} page_t;

/**
 * @brief Struct that represents a process that is using the memory structure.
 *
 */
typedef struct process {
    /**
     * @brief the process id.
     *
     */
    pid_t pid;
    /**
     * @brief How many pages are allocated to this process.
     *
     */
    int nPages;
    /**
     * @brief A table with fixed size (stablished by the `pager_t.nFrames`)
     * responsible for translating virtual address to fisic frames.
     *
     */
    page_t* table;
} proc_t;

typedef struct pager {
    /**
     * @brief The system default page size.
     *
     */
    long pageSize;
    /**
     * @brief Stores the number of bits used to represent a single page.
     *
     */
    int b2size;
    /**
     * @brief Mask used in frame-wise operations.
     *
     */
    int b2mask;
    /**
     * @brief Number of frames avaiable.
     *
     */
    int nFrames;
    /**
     * @brief Number of frames in use.
     *
     */
    int nFramesUsed;
    /**
     * @brief Number of blocks avaiable.
     *
     */
    int nBlocks;
    /**
     * @brief Number of blocks in use.
     *
     */
    int nBlocksUsed;
    /**
     * @brief Stores the first frame to be checked by the second chance alg.
     *
     */
    int id2nd;
    /**
     * @brief A vector storing all the frames avaiable.
     *
     */
    frame_t* frames;
    /**
     * @brief A vector storing all the backing blocks avaiable.
     *
     */
    block_t* blocks;
    /**
     * @brief A `process` linked list.
     *
     */
    dlist* procs;
    // ========== Mutexes ======================================================
    pthread_mutex_t procs_list_mutex;
} pager_t;

static pager_t pager;

/**
 * @brief Function that finds a process in the list of processes. If this pid is
 * non resident in the list, then returns NULL.
 *
 * @param pid the process id.
 * @return dnode* the pointer to the linked list node.
 */
dnode* find_process(pid_t pid);

/**
 * @brief Internal function to handle the page fault event. This function
 * assumes that the caller already has the possesion of the mutex lock guard.
 *
 * @param addr the base virtual address of this page.
 * @param proc the process who got a page fault.
 * @param pageID the page identifier.
 */
void internal_pager_fault(void* addr, proc_t* proc, int pageID);

/**
 * @brief Function that simulates second chance algorithm for page substitution.
 *
 * @param vaddr the virtual address of the page to be placed in the memory
 * @param proc the process requesting a frame allocation.
 * @param pageID the page identifier.
 *
 * @return int the frame ID allocated to this process to be mapped by this page.
 */
int secondChance(void* vaddr, proc_t* proc, int pageID);

// ==================== PAGER IMPLEMENTATION ===================================

void pager_init(int nframes, int nblocks) {
    // Get the page size (4KiB)
    pager.pageSize = sysconf(_SC_PAGESIZE);
    pager.b2mask = pager.pageSize - 1;
    int tmp = pager.pageSize;
    pager.b2size = -1;
    while(tmp) {
        pager.b2size++;
        tmp = tmp >> 1;
    }

    // Number of frames and backing blocks avaiable
    pager.nFrames = nframes;
    pager.nFramesUsed = 0;
    pager.nBlocks = nblocks;
    pager.nBlocksUsed = 0;

    // Allocate the frames and backing blocks and mark all of then as unused and
    // put then in the free lists
    pager.frames = (frame_t*)malloc(nframes * sizeof(frame_t*));
    pager.blocks = (block_t*)malloc(nblocks * sizeof(block_t*));

    for(int i = 0; i < nframes; i++) {
        pager.frames[i].pid = -1;
        pager.frames[i].flag = 0;
        pager.frames[i].pageID = -1;
    }
    for(int i = 0; i < nblocks; i++) pager.blocks[i].pid = -1;

    //
    pager.procs = dlist_create();
    pager.id2nd = 0;
    // Init the mutexes
    pthread_mutex_init(&pager.procs_list_mutex, NULL);
}

void pager_create(pid_t pid) {
    // Instantiate the new process beign connected to the memory structure
    proc_t* newProc = (proc_t*)malloc(sizeof(proc_t));
    newProc->pid = pid;
    newProc->nPages = 0;
    // Allocate a whole pages table (a process can't have more than 256 frames -
    // 1MiB - allocated)
    newProc->table = (page_t*)malloc(256 * sizeof(page_t));

    // Try to access the processes list
    pthread_mutex_lock(&pager.procs_list_mutex);

    // Insert the process in the list
    dlist_push_right(pager.procs, newProc);

    // Release the mutex
    pthread_mutex_unlock(&pager.procs_list_mutex);
}

void* pager_extend(pid_t pid) {
    // Try to access the processes list
    pthread_mutex_lock(&pager.procs_list_mutex);

    // Iterate over the process list and try to find this pid
    proc_t* proc = find_process(pid)->data;

    // There are no blocks avaiable to store any data allocated
    if(pager.nBlocksUsed == pager.nBlocks) {
        // Release the mutex
        pthread_mutex_unlock(&pager.procs_list_mutex);
        return NULL;
    }

    // Verify if the memory overflowed
    intptr_t vaddr = UVM_BASEADDR + pager.pageSize * proc->nPages;
    if(vaddr > UVM_MAXADDR) {
        // Release the mutex
        pthread_mutex_unlock(&pager.procs_list_mutex);
        return NULL;
    }

    // Searchs for an avaiable block
    for(int blockID = 0; blockID < pager.nBlocks; blockID++)
        if(pager.blocks[blockID].pid == -1) {
            // Sets this new page block
            proc->table[proc->nPages].blockID = blockID;
            pager.blocks[blockID].pid = pid;
            break;
        }

    // This page has never been used before
    proc->table[proc->nPages].flag_mask = 0b00;
    proc->table[proc->nPages].frameID = -1;
    // Since we have free blocks, it's 100% sure we can allocate a new page
    proc->nPages++;
    pager.nBlocksUsed++;

    // Release the mutex
    pthread_mutex_unlock(&pager.procs_list_mutex);
    return (void*)vaddr;
}

int secondChance(void* vaddr, proc_t* proc, int pageID) {
    while(1) {
        int frameID = pager.id2nd;
        pager.id2nd = (pager.id2nd + 1) % (pager.nFrames);

        // If this frame has not been used recently
        if(!pager.frames[frameID].flag) {
            frame_t* f = &pager.frames[frameID];
            // Finds the process whose page is going to the disk
            proc_t* affected_proc = find_process(f->pid)->data;

            void* virtual_base_affected =
                (void*)(UVM_BASEADDR + pager.pageSize * f->pageID);
            // Send the old data to disk if this data has been changed any time
            mmu_nonresident(affected_proc->pid, virtual_base_affected);
            if(affected_proc->table[f->pageID].flag_mask & 0b10) {
                mmu_disk_write(frameID,
                               affected_proc->table[f->pageID].blockID);
            }
            affected_proc->table[f->pageID].frameID = -1;
            // Make sure to indicate that the page is now totally syncronized
            // with the disk
            affected_proc->table[f->pageID].flag_mask &= ~0b10;

            // Brings the data from disk
            if(proc->table[pageID].flag_mask & 0b01) {
                mmu_disk_read(proc->table[pageID].blockID, frameID);
            }
            // If this page has never been used, then init it with zeros
            else {
                mmu_zero_fill(frameID);
            }
            // Gives this process the right to read in this frame
            // Fill this frame with zeros
            mmu_resident(proc->pid, vaddr, frameID, PROT_READ);

            return frameID;
        }
        frame_t* f = &pager.frames[frameID];
        // Reset the flag
        f->flag = 0;
        // Since the memory is full, we are 100% sure any frame is
        // pointed by some page
        void* base_addr_page =
            (void*)(UVM_BASEADDR + pager.pageSize * f->pageID);
        mmu_chprot(f->pid, base_addr_page, PROT_NONE);
    }

    // Unreachable piece of code
    printf("NUNCA PODE CHEGAR AQ\n");
    return -2;
}

void internal_pager_fault(void* addr, proc_t* proc, int pageID) {
    // If this page has a frame allocated and a seg fault happend, then it
    // needs a write access right
    if(proc->table[pageID].frameID != -1) {
        mmu_chprot(proc->pid, addr, PROT_READ | PROT_WRITE);
        // Set the bit indicating that the content of this slice of memory
        // was modified
        proc->table[pageID].flag_mask |= 0b11;
    }
    else {
        // Since the memory is full
        int frameID = 0;
        if(pager.nFramesUsed == pager.nFrames) {
            // We need to move out another process page to the disk
            frameID = secondChance(addr, proc, pageID);
        }
        // If the memory is not fully used
        else {
            pager.nFramesUsed++;
            // Search for a free frame in the frame array
            for(; frameID < pager.nFrames; frameID++)
                if(pager.frames[frameID].pid == -1) {
                    // Bring back content from disk
                    if(proc->table[pageID].flag_mask & 0b01) {
                        mmu_disk_read(proc->table[pageID].blockID, frameID);
                    }
                    // If this page has never been used, then fill it with
                    // zeros
                    else {
                        mmu_zero_fill(frameID);
                    }
                    // Gives this process the right to read in this frame
                    mmu_resident(proc->pid, addr, frameID, PROT_READ);

                    break;
                }
        }
        // Sets this new page frame
        proc->table[pageID].frameID = frameID;
        // Mark this frame as used
        pager.frames[frameID].pid = proc->pid;
        pager.frames[frameID].pageID = pageID;
    }
    // Make sure that at every page fault this frame flag is set
    pager.frames[proc->table[pageID].frameID].flag = 1;
}

void pager_fault(pid_t pid, void* addr) {
    addr = (void*)((intptr_t)addr & ~0x0000FFF);
    // Translate the virtual address into the page table index
    int pageID = ((intptr_t)addr - UVM_BASEADDR) >> pager.b2size;

    // Try to access the processes list
    pthread_mutex_lock(&pager.procs_list_mutex);

    // Iterate over the process list and try to find this pid
    proc_t* proc = find_process(pid)->data;

    // Handle the page fault
    internal_pager_fault(addr, proc, pageID);

    // Release the mutex
    pthread_mutex_unlock(&pager.procs_list_mutex);
}

int pager_syslog(pid_t pid, void* addr, size_t len) {
    if((intptr_t)addr < UVM_BASEADDR || UVM_MAXADDR < (intptr_t)addr) {
        errno = EINVAL;
        return -1;
    }
    if(!len) return 0;
    // Try to access the processes list
    pthread_mutex_lock(&pager.procs_list_mutex);

    // Iterate over the process list and try to find this pid
    proc_t* proc = find_process(pid)->data;

    intptr_t max_addr = UVM_BASEADDR + proc->nPages * pager.pageSize - 1;
    if((intptr_t)(addr + len) > max_addr) {
        // Release the mutex
        pthread_mutex_unlock(&pager.procs_list_mutex);
        errno = EINVAL;
        return -1;
    }

    int worked = 0;
    intptr_t vaddr = (intptr_t)addr;
    // Get the base offset of the first page
    int base_offset = vaddr & pager.b2mask;
    int howManyPages = ((len + base_offset - 1) >> pager.b2size) + 1;
    int i = 0;

    // Iterate over the pages to be printed
    for(int page = 0; page < howManyPages; page++) {
        // Get the page virtual memory base address
        intptr_t virtual_base_addr = vaddr & ~pager.b2mask;
        int pageID = (virtual_base_addr - UVM_BASEADDR) >> pager.b2size;
        // If it's trying to access an not allocated page, then error
        if(pageID >= proc->nPages) {
            errno = EINVAL;
            worked = -1;
            break;
        }

        // Then, it's safe to iterate over this page
        // If the page is not stored in the memory
        if(proc->table[pageID].frameID == -1) {
            // Signalize to the memory structure that this page is not in
            // memory
            internal_pager_fault((void*)virtual_base_addr, proc, pageID);
        }

        char* physical_base_addr =
            (char*)pmem + pager.pageSize * proc->table[pageID].frameID;
        int next_page_base = virtual_base_addr + pager.pageSize;

        // Iterate over this page safely
        for(; i < len && vaddr < next_page_base; i++, vaddr++) {
            printf("%02x",
                   (unsigned)physical_base_addr[vaddr - virtual_base_addr]);
        }
    }
    // Release the mutex
    pthread_mutex_unlock(&pager.procs_list_mutex);

    printf("\n");
    return worked;
}

void pager_destroy(pid_t pid) {
    // Try to access the processes list
    pthread_mutex_lock(&pager.procs_list_mutex);

    // Iterate over the process list and try to find this pid
    dnode* curr = find_process(pid);

    proc_t* proc = curr->data;
    // Recover all the resources allocated to this process
    while(--proc->nPages >= 0) {
        page_t* thisPage = &proc->table[proc->nPages];

        // If this page is resident in the memory
        if(thisPage->frameID != -1) {
            // Since this frame and block is no longer being used, set it as
            // free
            pager.frames[thisPage->frameID].pid = -1;
            pager.frames[thisPage->frameID].flag = 0;
            pager.frames[thisPage->frameID].pageID = -1;
            // Reduce the number of frames avaiable by reducing only the
            // memory resident pages
            pager.nFramesUsed--;
        }

        //
        pager.blocks[thisPage->blockID].pid = -1;
    }

    // Reduce the number of blocks being used
    pager.nBlocksUsed -= proc->nPages;

    // Make sure the process is freed
    free(proc->table);
    free(proc);

    // Remove from the list
    dlist_remove_from_node(pager.procs, curr);

    // Release the mutex
    pthread_mutex_unlock(&pager.procs_list_mutex);
}

dnode* find_process(pid_t pid) {
    // Iterate over the process list and try to find this pid
    dnode* curr;
    for(curr = pager.procs->head; curr; curr = curr->next) {
        proc_t* data = curr->data;
        if(data->pid == pid) break;
    }
    return curr;
}

// ==================== DLIST IMPLEMENTATION ===================================
struct dlist* dlist_create(void) /* {{{ */
{
    struct dlist* dl = malloc(sizeof(struct dlist));
    assert(dl);
    dl->head = NULL;
    dl->tail = NULL;
    dl->count = 0;
    return dl;
} /* }}} */

void* dlist_push_right(struct dlist* dl, void* data) /* {{{ */
{
    struct dnode* node = malloc(sizeof(struct dnode));
    assert(node);

    node->data = data;
    node->prev = dl->tail;
    node->next = NULL;

    if(dl->tail) dl->tail->next = node;
    dl->tail = node;

    if(dl->head == NULL) dl->head = node;

    dl->count++;
    return data;
} /* }}} */

void dlist_remove_from_node(struct dlist* dl, struct dnode* node) /* {{{ */
{
    // Make sure it is not used on empty list
    if(!dl->head) return;
    if(dl->count == 1) {
        dl->head = NULL;
        dl->tail = NULL;
    }
    else if(node == dl->head) {
        dl->head->next->prev = NULL;
        dl->head = dl->head->next;
        free(node);
    }
    else if(node == dl->tail) {
        node->prev->next = NULL;
        dl->tail = node->prev;
        free(node);
    }
    else {
        struct dnode* prev = node->prev;
        struct dnode* next = node->next;
        prev->next = next;
        next->prev = prev;
        free(node);
    }

    dl->count--;
} /* {{{ */