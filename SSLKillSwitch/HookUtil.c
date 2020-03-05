

#import <stdlib.h>
#import <stdio.h>
#import <dlfcn.h>
#import "HookUtil.h"

// Rewrite fishhook from FaceBook
#import <string.h>
#import <mach-o/dyld.h>
#import <mach-o/nlist.h>

#include <CoreFoundation/CoreFoundation.h>

#if defined(_MAC64) || defined(__LP64__)
typedef struct mach_header_64 mach_header_t;
typedef struct segment_command_64 segment_command_t;
typedef struct section_64 section_t;
typedef struct nlist_64 nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT_64
#else
typedef struct mach_header mach_header_t;
typedef struct segment_command segment_command_t;
typedef struct section section_t;
typedef struct nlist nlist_t;
#define LC_SEGMENT_ARCH_DEPENDENT LC_SEGMENT
#endif

struct FHRebinding
{
	const char *name;
	void *replacement;
	void **replaced;
};

static struct FHRebindingsEntry
{
	struct FHRebinding *rebindings;
	size_t count;
	struct FHRebindingsEntry *next;
} *_rebindings_head = NULL;

static void FHRebindSymbolsForImage(const struct mach_header *header, intptr_t slide)
{
	Dl_info info;
	if (dladdr(header, &info) == 0)
	{
		return;
	}
	
	segment_command_t *cur_seg_cmd;
	segment_command_t *linkedit_segment = NULL;
	struct symtab_command* symtab_cmd = NULL;
	struct dysymtab_command* dysymtab_cmd = NULL;
	
	uintptr_t cur = (uintptr_t)header + sizeof(mach_header_t);
	for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize)
	{
		cur_seg_cmd = (segment_command_t *)cur;
		if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT)
		{
			if (strcmp(cur_seg_cmd->segname, SEG_LINKEDIT) == 0)
			{
				linkedit_segment = cur_seg_cmd;
			}
		}
		else
		if (cur_seg_cmd->cmd == LC_SYMTAB)
		{
			symtab_cmd = (struct symtab_command*)cur_seg_cmd;
		}
		else if (cur_seg_cmd->cmd == LC_DYSYMTAB)
		{
			dysymtab_cmd = (struct dysymtab_command*)cur_seg_cmd;
		}
	}
	
	if (!symtab_cmd || !dysymtab_cmd || !linkedit_segment || !dysymtab_cmd->nindirectsyms)
	{
		return;
	}
	
	// Find base symbol/string table addresses
	uintptr_t linkedit_base = (uintptr_t)slide + linkedit_segment->vmaddr - linkedit_segment->fileoff;
	nlist_t *symtab = (nlist_t *)(linkedit_base + symtab_cmd->symoff);
	char *strtab = (char *)(linkedit_base + symtab_cmd->stroff);
	
	// Get indirect symbol table (array of uint32_t indices into symbol table)
	uint32_t *indirect_symtab = (uint32_t *)(linkedit_base + dysymtab_cmd->indirectsymoff);
	
	cur = (uintptr_t)header + sizeof(mach_header_t);
	for (uint i = 0; i < header->ncmds; i++, cur += cur_seg_cmd->cmdsize)
	{
		cur_seg_cmd = (segment_command_t *)cur;
		if (cur_seg_cmd->cmd == LC_SEGMENT_ARCH_DEPENDENT)
		{
			if (strcmp(cur_seg_cmd->segname, SEG_DATA) != 0 && strcmp(cur_seg_cmd->segname, "__DATA_CONST") != 0)
			{
				continue;
			}
			for (uint j = 0; j < cur_seg_cmd->nsects; j++)
			{
				section_t *sect =
				(section_t *)(cur + sizeof(segment_command_t)) + j;
				if (((sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) || ((sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS))
				{
					uint32_t *indirect_symbol_indices = indirect_symtab + sect->reserved1;
					void **indirect_symbol_bindings = (void **)((uintptr_t)slide + sect->addr);
					for (uint i = 0; i < sect->size / sizeof(void *); i++)
					{
						uint32_t symtab_index = indirect_symbol_indices[i];
						if (symtab_index == INDIRECT_SYMBOL_ABS || symtab_index == INDIRECT_SYMBOL_LOCAL ||
							symtab_index == (INDIRECT_SYMBOL_LOCAL   | INDIRECT_SYMBOL_ABS))
						{
							continue;
						}
						uint32_t strtab_offset = symtab[symtab_index].n_un.n_strx;
						char *symbol_name = strtab + strtab_offset;
						if (strnlen(symbol_name, 2) < 2)
						{
							continue;
						}
						struct FHRebindingsEntry *cur = _rebindings_head;
						while (cur)
						{
							for (uint j = 0; j < cur->count; j++)
							{
								if (strcmp(&symbol_name[1], cur->rebindings[j].name) == 0)
								{
									if (cur->rebindings[j].replaced != NULL && indirect_symbol_bindings[i] != cur->rebindings[j].replacement)
									{
										*(cur->rebindings[j].replaced) = indirect_symbol_bindings[i];
									}
									indirect_symbol_bindings[i] = cur->rebindings[j].replacement;
									goto symbol_loop;
								}
							}
							cur = cur->next;
						}
					symbol_loop:;
					}
				}
			}
		}
	}
}

void HUHookFunction(const char *lib, const char *func, void *hook, void **old)
{	
	struct FHRebindingsEntry *new_entry = (struct FHRebindingsEntry *)malloc(sizeof(struct FHRebindingsEntry));
	if (!new_entry)
	{
		*old = NULL;
		return;
	}
	new_entry->rebindings = (struct FHRebinding *)malloc(sizeof(struct FHRebinding));
	if (!new_entry->rebindings)
	{
		free(new_entry);
		*old = NULL;
		return;
	}
	
	new_entry->rebindings[0].name = func;
	new_entry->rebindings[0].replaced = old;
	new_entry->rebindings[0].replacement = hook;
	new_entry->count = 1;
	new_entry->next = _rebindings_head;
	_rebindings_head = new_entry;
	
	// If this was the first call, register callback for image additions (which is also invoked for existing images, otherwise, just run on existing images
	if (!_rebindings_head->next)
	{
		_dyld_register_func_for_add_image(FHRebindSymbolsForImage);
	}
	else
	{
		uint32_t c = _dyld_image_count();
		for (uint32_t i = 0; i < c; i++)
		{
			FHRebindSymbolsForImage(_dyld_get_image_header(i), _dyld_get_image_vmaddr_slide(i));
		}
	}
}