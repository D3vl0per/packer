// Researched and created by 12Boti
package elf

import (
	"encoding/binary"
	"os"
)

// See https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
// The code only works for 64-bit little-endian ELF files

func ELFSize(f *os.File) uint64 {
	size := uint64(0)

	e_phoff := ReadU64(f, 0x20)
	e_phentsize := uint64(ReadU16(f, 0x36))
	e_phnum := uint64(ReadU16(f, 0x38))
	size = Max(size, e_phoff+e_phentsize*e_phnum)

	e_shoff := ReadU64(f, 0x28)
	e_shentsize := uint64(ReadU16(f, 0x3A))
	e_shnum := uint64(ReadU16(f, 0x3C))
	size = Max(size, e_shoff+e_shentsize*e_shnum)

	for i := uint64(0); i < e_phnum; i++ {
		p_offset := ReadU64(f, e_phoff+e_phentsize*i+0x08)
		p_filesz := ReadU64(f, e_phoff+e_phentsize*i+0x20)
		p_align := ReadU64(f, e_phoff+e_phentsize*i+0x30)
		if p_align == 0 {
			p_align = 1
		}
		size = Max(size, (p_offset+p_filesz+p_align-1)/p_align*p_align)
	}
	return size
}

func ReadU64(f *os.File, off uint64) uint64 {
	buf := make([]byte, 8)
	_, err := f.ReadAt(buf, int64(off))
	if err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint64(buf)
}

func ReadU16(f *os.File, off uint64) uint16 {
	buf := make([]byte, 2)
	_, err := f.ReadAt(buf, int64(off))
	if err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint16(buf)
}

func Max(a, b uint64) uint64 {
	if a > b {
		return a
	} else {
		return b
	}
}

func FileELFSize(path string) (uint64, error) {

	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return 0, err
	} else if err != nil {
		return 0, err
	}

	exec, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer exec.Close()

	size := ELFSize(exec)

	return size, nil
}

func FileSize(path string) (int64, error) {

	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return 0, err
	} else if err != nil {
		return 0, err
	}

	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}

	return info.Size(), nil
}

func SizeDiff(path string) (int64, error) {
	execSize, err := FileSize(path)
	if err != nil {
		return 0, err
	}

	exec, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer exec.Close()
	return execSize - int64(ELFSize(exec)), nil
}

// If true is returned, the ELF size and real size of the executable is different
func CheckSizeDiff(path string) (bool, error) {
	diff, err := SizeDiff(path)
	if err != nil {
		return false, err
	}
	if diff != 0 {
		return true, nil
	}
	return false, nil
}

func ExecutableSize() (string, int64, error) {
	exec, err := os.Executable()
	if err != nil {
		return "", 0, err
	}

	size, err := FileSize(exec)
	if err != nil {
		return "", 0, err
	}

	return exec, size, nil
}

func ExtractPayload(path string) ([]byte, error) {
	exec, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	elfSize := ELFSize(exec)

	fileSize, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	offset := fileSize.Size() - int64(elfSize)

	payload := make([]byte, offset)
	_, err = exec.ReadAt(payload, int64(elfSize))
	if err != nil {
		return nil, err
	}

	return payload, nil
}

func ExtractBinary(path string) ([]byte, error) {

	exec, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	eSize := int64(ELFSize(exec))

	binary := make([]byte, eSize)
	_, err = exec.ReadAt(binary, 0)
	if err != nil {
		return nil, err
	}

	return binary, nil
}

func GetExecutables() (*os.File, string, error) {
	exec, err := os.Executable()
	if err != nil {
		return &os.File{}, exec, err
	}

	file, err := os.Open(exec)
	if err != nil {
		return &os.File{}, exec, err
	}
	return file, exec, nil
}
