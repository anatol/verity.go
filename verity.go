package verity

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"unsafe"

	"github.com/anatol/devmapper.go"
)

const signature = "verity\x00\x00"

// superblock for verity-formatted device
// specification can be found here https://gitlab.com/cryptsetup/cryptsetup/-/wikis/DMVerity
type superblock struct {
	signature     [8]byte // must be "verity\0\0"
	version       uint32
	hashType      uint32
	uuid          [16]byte
	algorithm     [32]byte
	dataBlockSize uint32
	hashBlockSize uint32
	dataBlocks    uint64
	saltSize      uint16
	_             [6]byte
	salt          [256]byte
	_             [168]byte
}

func Open(name string, dataDevice, hashDevice string, digest string) error {
	f, err := os.Open(hashDevice)
	if err != nil {
		return err
	}
	defer f.Close()

	data := make([]byte, 512)
	if _, err := f.Read(data); err != nil {
		return err
	}
	sb := (*superblock)(unsafe.Pointer(&data[0]))

	if bytes.Compare([]byte(signature), sb.signature[:]) != 0 {
		return fmt.Errorf("%s does not contain verity superblock", dataDevice)
	}

	v := devmapper.VerityTable{
		Length:         sb.dataBlocks * 8, // size of a verity block is 4096 bytes while size of dm-mapper block is 512
		HashType:       uint64(sb.version),
		DataDevice:     dataDevice,
		HashDevice:     hashDevice,
		DataBlockSize:  uint64(sb.dataBlockSize),
		HashBlockSize:  uint64(sb.hashBlockSize),
		NumDataBlocks:  sb.dataBlocks,
		HashStartBlock: 1, // right after this superblock
		Algorithm:      fixedArrayToString(sb.algorithm[:]),
		Salt:           hex.EncodeToString(sb.salt[:sb.saltSize]),
		Digest:         digest,
	}
	uuid := fmt.Sprintf("CRYPT-VERITY-%s-%s", hex.EncodeToString(sb.uuid[:]), name) // See dm_prepare_uuid()
	return devmapper.CreateAndLoad(name, uuid, devmapper.ReadOnlyFlag, v)
}

func Close(name string) error {
	return devmapper.Remove(name)
}

func fixedArrayToString(buff []byte) string {
	idx := bytes.IndexByte(buff, 0)
	if idx != -1 {
		buff = buff[:idx]
	}
	return string(buff)
}
