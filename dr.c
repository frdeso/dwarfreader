#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <dwarf.h>
#include <elf.h>
#include <gelf.h>
#include <libdwarf.h>
#include <libelf.h>
#include <popt.h>

#define BUFF_SIZE 128

void print_probe_location(ino_t inode, long offset)
{
	printf("inode: %ld, offset: 0x%04x\n", inode,(int) offset);
}

ino_t get_inode_num(char *path)
{
	struct stat sb;
	int ret;
	ret = stat(path, &sb);
	if (ret != 0) {
		perror("Error during stat of binary file");
		return -1;
	}

	return sb.st_ino;
}
/*
 * Returns 1 if the Debug Info Entry is for a function name passed on function
 * call.
 */
int is_function(Dwarf_Die die, char *func)
{
	char* die_name = 0;
	int ret;
	Dwarf_Half tag;
	Dwarf_Error err;

	int rc = dwarf_diename(die, &die_name, &err);

	if (rc == DW_DLV_ERROR) {
        	fprintf(stderr,"Error in dwarf_diename\n");
	}else if (rc == DW_DLV_NO_ENTRY) {
        	ret = -1;
        	goto err;
	}

	if (dwarf_tag(die, &tag, &err) != DW_DLV_OK) {
        	fprintf(stderr,"Error in dwarf_tag\n");
        	ret = -1;
        	goto err;
        }

	/* Only interested in subprogram DIEs here */
	if (tag != DW_TAG_subprogram) {
        	ret = -1;
        	goto err;
        }

	// zero means same string
	ret = strncmp(func, die_name, BUFF_SIZE);
	if (ret != 0) {
		/* No match */
		ret = 0;
	} else {
		/* Match */
		ret = 1;
	}

err:
	return ret;
}
int get_function_lowpc(Dwarf_Die die)
{
	int i, ret;
	Dwarf_Error dwarf_err;
	Dwarf_Attribute* attrs;
	Dwarf_Signed attrcount;
	Dwarf_Addr lowpc;

	if (dwarf_attrlist(die, &attrs, &attrcount, &dwarf_err) != DW_DLV_OK) {
		fprintf(stderr,"Error in dwarf_attlist: %s\n", dwarf_errmsg(dwarf_err));
		goto err;
	}

	/*
	 * Iterate over all the attribute on this entry to find 
	 * the low pc which is the first instruction of this unit
	 */
	ret = -1;
	for (i = 0; i < attrcount; ++i) {
		Dwarf_Half attrcode;
		if (dwarf_whatattr(attrs[i], &attrcode, &dwarf_err) != DW_DLV_OK) {
			fprintf(stderr,"Error in dwarf_whatattr\n");
			ret = -1;
			goto err;
		}
		if (attrcode == DW_AT_low_pc) {
			dwarf_formaddr(attrs[i], &lowpc, &dwarf_err);
			ret = lowpc;
			break;
		}
	}

err:
	return ret;
}
unsigned long get_function_offset(Dwarf_Debug dbg, char *func)
{
	int ret;
	char *die_name = malloc(BUFF_SIZE * sizeof(char));
	Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header;
	Dwarf_Half version_stamp, address_size;
	Dwarf_Error err;
	Dwarf_Signed attrcount;
	Dwarf_Die no_die = 0, cu_die, child_die;

	int found = 0;
	/* Find compilation unit header */
	while (dwarf_next_cu_header( dbg,
			&cu_header_length,
			&version_stamp,
			&abbrev_offset,
			&address_size,
			&next_cu_header,
			&err) == DW_DLV_OK && found != 1) {

		/* Expect the CU to have a single sibling - a DIE */
		if (dwarf_siblingof(dbg, no_die, &cu_die, &err) == DW_DLV_ERROR) {
			fprintf(stderr, "Error getting sibling of CU %s\n", 
				dwarf_errmsg(err));
			ret = -1;
			goto err;
		}

		/* Expect the CU DIE to have children */
		if (dwarf_child(cu_die, &child_die, &err) == DW_DLV_ERROR) {
			fprintf(stderr, "Error getting child of CU DIE\n");
			ret = -1;
			goto err;
		}

		/* Now go over all children DIEs */
		while (!found) {
			int rc;
			int match = is_function(child_die, func);
			if (match == 1) {
				ret = get_function_lowpc(child_die);
				if (ret != -1) {
					found = 1;
				}
			}

			if (!found) {
				rc = dwarf_siblingof(dbg, child_die, &child_die, &err);

				if (rc == DW_DLV_ERROR) {
					fprintf(stderr,"Error getting sibling of DIE\n");
					ret = -1;
					break; /* done */
				} else if (rc == DW_DLV_NO_ENTRY) {
					ret = -1;
					break; /* done */
				}
			}
		}
	}
err:
	return ret;
}

/*
 * Extract the offset from the beginning of a function from the probe definition
 * assuming the following format: "function+0xDEADBEEF"
 * If no offset is specified, we set the offset to zero
 */
int extract_target_offset(char *def, unsigned long *offs)
{
	int ret, nb_matches;
	char *offs_str;

	offs_str = malloc(BUFF_SIZE * sizeof(char));
	if (!offs_str) {
		fprintf(stderr,"Error allocating array for probe offset");
		return -1;
	}

	/*
	 * Copy the offset out of the definition by spliting on the first
	 * plus sign
	 */

	nb_matches = sscanf(def, "%*[^+]+%s", offs_str);

	/* 
	 * if no matches are found, it means that no offsets were specified, we
	 * set the offset to zero
	 */
	if (nb_matches == 0) {
		*offs= 0;
	} else if (nb_matches == 1) {

		errno = 0;
		*offs = strtol(offs_str, NULL, 16);
		/* Check for out of bound conversion */
		if (errno == ERANGE && (*offs == LONG_MAX || *offs == LONG_MIN)) {
              		perror("offset out of range");
        		ret = -1;
		}
		/* Check for strtol error */
		if (errno != 0 && *offs == 0) {
              		perror("No digits detected");
        		ret = -1;
        	}
	} else {
		/* If we find more than one '+' it's an error */
		fprintf(stderr,"Error parsing probe definition, more than one '+' found");
		ret = -1;
	}

	free(offs_str);
	return ret;
}

/*
 * Convert the virtual address in binary to the offset of the instruction in the
 * binary file.
 * Returns the offset on success,
 * Returns -1 in case of failure
 */
long convert_addr_to_offset(char *target_path, long addr)
{
	int ret;
	int fd;
	int text_section_found;
	long text_section_offset, text_section_addr, offset_in_section;
	char *section_name;
	Elf *elf_handle;
	size_t section_index;
	Elf_Scn *elf_section;
	GElf_Shdr elf_section_header;

	fd = open(target_path, O_RDONLY);
    	if (fd < 0) {
        	perror("Failed to open binary file");
    		return -1;
    	}

    	if (elf_version(EV_CURRENT) == EV_NONE) {
		fprintf(stderr, "ELF library initialization failed : %s", elf_errmsg(-1));
		ret = -1;
    		goto err;
    	}

	elf_handle = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf_handle) {
		fprintf (stderr , "elf_begin() failed: %s." , elf_errmsg ( -1));
		ret = -1;
    		goto err;
	}

	ret = elf_getshdrstrndx (elf_handle, &section_index);
	if (ret) {
		fprintf(stderr, "ELF get header index failed : %s", elf_errmsg(-1));
		ret = -1;
		goto err2;
	}
	elf_section = NULL;

	text_section_found = 0;

	while ((elf_section = elf_nextscn(elf_handle, elf_section)) != NULL ) {
		gelf_getshdr(elf_section, &elf_section_header) ;
		section_name = elf_strptr(elf_handle, section_index, elf_section_header.sh_name);

		if (strncmp(section_name, ".text", 5) == 0) {
			text_section_offset = elf_section_header.sh_offset;
			text_section_addr = elf_section_header.sh_addr;
			text_section_found = 1;
			break;
		}
	}

	if (!text_section_found) {
		fprintf(stderr, "Text section not found in binary\n");
		ret = -1;
		goto err2;
	}

	/*
	 * To find the offset of the addr from the beginning of the .text
	 * section.
	 */
	offset_in_section = addr - text_section_addr;

	/*
	 * Add the offset in the section to the offset of the section from the
	 * beginning of the binary.
	 */

	ret = text_section_offset + offset_in_section;

err2:
	elf_end(elf_handle);
err:
	close(fd);
	return ret;
}

/*
 * Convert a probe definition consisting of binary file and an address to the
 * inode number and offset in the file
 */
int probe_point_from_address(char *target, char *probe_def)
{
	int ret = 0;
	unsigned long addr;
	long offset;
	ino_t inode_number;

	/* Get the inode for that path */
	inode_number = get_inode_num(target);
	if (inode_number == -1) {
		goto err;
	}



	/* Extract virtual address from the probe definition */
	errno = 0;
	addr = strtol(probe_def, NULL, 16);

	/* Check for out of bound conversion */
	if (errno == ERANGE && (addr == LONG_MAX || addr == LONG_MIN)) {
              	perror("Address out of range");
        	ret = -1;
	}

	if (errno != 0 && addr == 0) {
              	perror("No digits detected");
        	ret = -1;
        }

	/* Use elf information to translate the address to offset */
	offset = convert_addr_to_offset(target, addr);
	if (offset == -1) {
		ret = offset;
		goto err;
	}

	print_probe_location(inode_number, (int)offset);

err:
	return ret;
}

/*
 * Convert a probe definition consisting of binary file and a function
 * name+offset to the inode number and offset in the file
 */
int probe_point_from_function(char *target, char *probe_def)
{
	int ret = 0;
	int fd;
	unsigned long offset_from_func, offset;
	char *function;

	ino_t inode_number;
	Dwarf_Debug dbg;
	Dwarf_Error dwarf_err;


	/* Get the inode for that path */
	inode_number = get_inode_num(target);
	if (inode_number == -1) {
		ret = -1;
	}


	/* Extract function name */

	function = malloc(BUFF_SIZE * sizeof(char));
	if (!function) {
		fprintf(stderr,"Error allocating array for the probe definition");
		return -1;
	}

	ret = sscanf(probe_def, "%[^+]+%*s", function);

	/* Return error if not exactly 1 match is found */
	if (ret != 1){
		fprintf(stderr,"Error extracting the function name out of the probe definition");
		return -1;
	}

	/* Extract the offset if present */
	ret = sscanf(probe_def, "%*[^+]+%ld", &offset_from_func);
	if (!ret) {
		/* If no match we set the offset to zero*/
		offset_from_func = 0;
	}

	/* Find address of the function */
	if ((fd = open(target, O_RDONLY)) < 0) {
		fprintf(stderr, "Open on %s failed\n", target);
		ret = -1;
		goto err;
	}

	/* Init libdwarf */
	if (dwarf_init(fd, DW_DLC_READ, 0, 0, &dbg, &dwarf_err) != DW_DLV_OK) {
		fprintf(stderr, "Failed DWARF initialization\n");
		//TODO: use dwarf err feature to print the error
		ret = -1;
		goto err;
	}

	/* Get the offset of the function in the binary */
	long func_off = get_function_offset(dbg, function);
	if (func_off == -1) {
		fprintf(stderr, "Failed to find the function offset\n");
		ret = -1;
		goto err2;
	}

	/* FIXME:Check if offset is within the bound of the function */

	/* Find the physical offset inside the file */
	offset = convert_addr_to_offset(target, func_off + offset_from_func);
	if (offset == -1) {
		ret = -1;
		goto err2;
	}

	print_probe_location(inode_number, (int)offset);
err3:
	// teardown libdwarf
	if (dwarf_finish(dbg, &dwarf_err) != DW_DLV_OK) {
		fprintf(stderr, "Failed DWARF finalization\n");
	}
err2:
	close(fd);
	free(function);
err:
	return ret;
}

int check_filename_matches(char *path, char *file)
{
	char *substring = strstr(path, file);
	if (substring == NULL)
		return 0;
	else
		return 1;
}

long get_addr_src_line(Dwarf_Debug dbg, char *file, int line_no) 
{
	Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header;
	Dwarf_Half version_stamp, address_size;
	Dwarf_Error err;
	Dwarf_Die no_die = 0, cu_die;
	int n,ret;
	Dwarf_Error de;
	char *filename;
	Dwarf_Line *lines;
	Dwarf_Signed nlines;
	Dwarf_Addr lineaddr;
	Dwarf_Unsigned lineno;

	int found = 0;
	/* Find compilation unit header */
	while (dwarf_next_cu_header(
				 dbg,
				 &cu_header_length,
				 &version_stamp,
				 &abbrev_offset,
				 &address_size,
				 &next_cu_header,
				 &err) == DW_DLV_OK && found == 0){

		/* Expect the CU to have a single sibling - a DIE */
		if (dwarf_siblingof(dbg, no_die, &cu_die, &err) == DW_DLV_ERROR){
			fprintf(stderr, "Error getting sibling of CU\n");
			ret = -1;
			goto err;
		}

		if (dwarf_srclines(cu_die, &lines, &nlines, &de) != DW_DLV_OK) {
			fprintf(stderr, "dwarf_srclines: %s", dwarf_errmsg(de));
		}
		ret = -1;
		for (n = 0; n < nlines; n++) {
			/* Retrieve the file name for this descriptor. */
			if (dwarf_linesrc(lines[n], &filename, &de)) {
				fprintf(stderr, "dwarf_linesrc: %s", dwarf_errmsg(de));
				ret = -1;
				goto err;
			}

			char code = malloc(BUFF_SIZE * sizeof(char));
			dwarf_lineno(lines[n], &lineno, &de);
			//printf("file:%s, lineno: %d\n\n", filename, lineno);
			if (check_filename_matches(filename, file)) {
				/* Retrieve the line number in the source file. */
				if (dwarf_lineno(lines[n], &lineno, &de)) {
					fprintf(stderr, "dwarf_lineno: %s", dwarf_errmsg(de));
					ret = -1;
					goto err;
				}
				if (lineno == line_no) {
					/* Retrieve the virtual address associated with this line. */
					if (dwarf_lineaddr(lines[n], &lineaddr, &de)) {
						fprintf(stderr, "dwarf_lineaddr: %s", dwarf_errmsg(de));
						ret = -1;
						goto err;
					}

					ret = lineaddr;
					found = 1;
					break;
				}
			}
		}
	}

err:
	return ret;
}
int probe_point_from_file_location(char *target, char *probe_def)
{
	int ret, fd;
	int src_lineno = 0;
	long offset;
	char  *src_filename;
	Dwarf_Debug dwarf_dbg;
	Dwarf_Error dwarf_err;
	ino_t inode_number;

	//Get the inode number of that binary
	inode_number = get_inode_num(target);
	if (inode_number == -1) {
		ret = -1;
		goto err;
	}

	src_filename = malloc(BUFF_SIZE * sizeof(char));
	if (src_filename == NULL) {
		fprintf(stderr, "Failed to allocate buffer");
		ret = -1;
		goto err;
	}

	ret = sscanf(probe_def,"%[^:]:%d", src_filename, &src_lineno);
	if (ret != 2) {
		/* if we don't get 2 matches we exit with error */
        	fprintf(stderr, "Probe definition malformed %s", probe_def);
		ret = -1;
		goto err2;
	}

	if ((fd = open(target, O_RDONLY)) < 0) {
		fprintf(stderr, "Open on %s failed\n", target);
		ret = -1;
		goto err2;
	}
	// init libdwarf
	if (dwarf_init(fd, DW_DLC_READ, 0, 0, &dwarf_dbg, &dwarf_err) != DW_DLV_OK) {
		fprintf(stderr, "Failed DWARF initialization\n");
		ret = -1;
		goto err3;
	}

	long line_addr = get_addr_src_line(dwarf_dbg, src_filename, src_lineno);
	if (line_addr == -1) {
		fprintf(stderr,"Error finding the address of the line\n");
		ret = -1;
		goto err3;
	}

	/* Find the physical offset inside the file */
	offset = convert_addr_to_offset(target, line_addr);
	if (offset == -1) {
		ret = -1;
		goto err3;
	}
	print_probe_location(inode_number, (int)offset);

err3:
	close(fd);
err2:
	free(src_filename);
err:
	return ret;
}


int main(int argc, char *argv[])
{
	int ret;
	if (argc != 4)
	{
		fprintf(stderr,"Invalid number of arguments: %d\n", argc);
		return -1;
	}
	char *target = argv[2];
	char *probe_def = argv[3];
	switch(argv[1][1])
	{
	case 'a':
		ret = probe_point_from_address(target, probe_def);
		break;
	case 'b':
		ret = probe_point_from_function(target, probe_def);
		break;
	case 'c':
		ret = probe_point_from_file_location(target, probe_def);
		break;
	default:
		fprintf(stderr,"Invalid probe definition type: %s\n", argv[1]);
		ret = -1;
		break;
	}
	return ret;
