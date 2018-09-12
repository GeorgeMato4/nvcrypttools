OUTPUT_FORMAT("elf32-littlearm")
OUTPUT_ARCH(arm)
ENTRY(Start)
SECTIONS
{
	. = 0x40007800;
	text_start = .;
	.text : {
		*(.text)
	}

	/DISCARD/ : { *(.dynstr*) }
	/DISCARD/ : { *(.dynamic*) }
	/DISCARD/ : { *(.plt*) }
	/DISCARD/ : { *(.interp*) }
	/DISCARD/ : { *(.gnu*) }
	/DISCARD/ : { *(.data*) }
	/DISCARD/ : { *(.rodata*) }
	/DISCARD/ : { *(.debug_line) }
	/DISCARD/ : { *(.debug_info) }
	/DISCARD/ : { *(.debug_abbrev) }
	/DISCARD/ : { *(.debug_aranges) }
	/DISCARD/ : { *(.note.gnu.gold-version) }
	/DISCARD/ : { *(.ARM.attributes) }
}
