package elf_test

import (
	"testing"

	"github.com/D3vl0per/packer/internal/elf"
	r "github.com/stretchr/testify/require"
)

func TestCheckDiffSize(t *testing.T) {
	originalExecutable := "/home/d3v/Documents/Projects/packer/test_binary/packer"
	autoconfExecutable := "/home/d3v/Documents/Projects/packer/test_binary/packer-autoconf"

	oExecSize, err := elf.FileSize(originalExecutable)
	r.Nil(t, err)
	t.Logf("Original Executable Size: %d", oExecSize)

	oExecElfSize,err := elf.FileELFSize(originalExecutable)
	r.Nil(t, err)
	t.Logf("Original Executable ELF Size: %d", oExecElfSize)

	aExecSize, err := elf.FileSize(autoconfExecutable)
	r.Nil(t, err)
	t.Logf("Autoconf Executable Size: %d", aExecSize)

	aExecElfSize,err := elf.FileELFSize(autoconfExecutable)
	r.Nil(t, err)
	t.Logf("Autoconf Executable ELF Size: %d", aExecElfSize)

	isNotDiff, err := elf.CheckSizeDiff(originalExecutable)
	r.Nil(t, err)
	r.False(t, isNotDiff)
	t.Log("Original Executable Size and ELF Size is not different")

	isDiff, err := elf.CheckSizeDiff(autoconfExecutable)
	r.Nil(t, err)
	r.True(t, isDiff)
	t.Log("Autoconf Executable Size and ELF Size is different")


	

}
