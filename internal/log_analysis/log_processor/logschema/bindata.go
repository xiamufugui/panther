// Code generated for package logschema by go-bindata DO NOT EDIT. (@generated)
// sources:
// schema.json
package logschema

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func bindataRead(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}

	var buf bytes.Buffer
	_, err = io.Copy(&buf, gz)
	clErr := gz.Close()

	if err != nil {
		return nil, fmt.Errorf("Read %q: %v", name, err)
	}
	if clErr != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

type asset struct {
	bytes []byte
	info  os.FileInfo
}

type bindataFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

// Name return file name
func (fi bindataFileInfo) Name() string {
	return fi.name
}

// Size return file size
func (fi bindataFileInfo) Size() int64 {
	return fi.size
}

// Mode return file mode
func (fi bindataFileInfo) Mode() os.FileMode {
	return fi.mode
}

// Mode return file modify time
func (fi bindataFileInfo) ModTime() time.Time {
	return fi.modTime
}

// IsDir return file whether a directory
func (fi bindataFileInfo) IsDir() bool {
	return fi.mode&os.ModeDir != 0
}

// Sys return file is sys mode
func (fi bindataFileInfo) Sys() interface{} {
	return nil
}

var _schemaJson = []byte("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff\xec\x5a\x6d\x6f\xdb\xb6\x13\x7f\x9f\x4f\x41\xb0\xf9\xbf\x69\xed\x3a\xfd\x67\xdd\xd0\xbc\x19\xda\xac\x45\x0b\xf4\x21\x68\xd6\x16\x6b\xec\x04\x8c\x74\xb2\x99\x51\xa4\x46\x52\x79\x68\xe1\xef\x3e\xe8\xc9\x12\x29\x52\x96\xe2\xb8\xc3\xba\xbe\x48\x62\x93\x77\xc7\xbb\xe3\xef\x8e\xc7\x63\xbe\xee\x20\x84\x77\x55\xb0\x80\x98\xe0\x03\x84\x17\x5a\x27\x07\x93\xc9\x85\x12\x7c\x5c\x8c\x3e\x14\x72\x3e\x09\x25\x89\xf4\x78\xef\x97\x49\x31\x76\x0f\x8f\x32\x3e\x4d\x35\x83\x8c\xeb\x88\x70\xbd\x00\x89\x98\x98\xa3\x52\x56\x4e\xb0\x4b\xc3\x4a\xa8\x3a\x98\x4c\x64\xca\x93\x82\xf2\x21\x15\xa5\x28\x35\x61\x62\xae\x12\x08\x26\x97\x7b\x25\x93\x84\x28\xe3\xba\x37\x09\x21\xa2\x9c\x6a\x2a\xb8\x2a\xa9\x8f\x13\x08\x0a\xaa\xc6\x1c\x3e\x40\x99\x19\x08\xe1\x06\x51\x35\x96\xa9\x79\x93\xe4\x5a\x8a\xf3\x0b\x08\x74\xce\x9e\x8f\x27\x52\x24\x20\x35\x05\xd5\xa0\x46\x08\x5f\x82\x54\x54\x70\x63\x10\x21\x1c\x08\xae\x34\x3e\x40\x7b\xab\xc1\xe5\xa8\x66\x5a\xb9\xd0\xe0\xa9\x96\x56\x5a\x52\x3e\xc7\xa3\xe6\x5c\x4c\xf9\x6b\xe0\x73\xbd\xc0\x07\x68\xdf\x98\x49\x88\xd6\x20\x33\x05\xf0\xe9\xc9\xd3\xf1\xe7\x59\xf6\x8b\x8c\xbf\xec\x8d\x9f\xcc\x1e\xec\x62\xe7\xfa\x21\xa8\x40\xd2\x44\x3b\x14\xb7\x94\x70\xb2\x4b\x88\x40\x02\x0f\xe0\xc3\xfb\xd7\x43\x8c\x88\x84\x8c\x49\xe6\x15\x9c\x4a\xea\x16\x9d\x10\xa9\x40\xfa\x84\x5a\x9b\x52\x78\x86\x5c\x1f\x35\xf7\xe6\x91\xed\xb7\x8e\x59\xcf\xa6\x16\x3b\xa8\x2e\x5b\x83\x08\x61\xc1\xe1\x5d\x86\xb8\x13\x6b\x02\xb5\x48\x73\x72\x37\x3e\x0b\x2b\x0f\x8f\x3f\x7e\xa2\x7a\xf1\x12\x48\x08\x12\xb7\xb8\x97\xa3\x3b\x5b\x42\xa4\xda\xbb\x8a\x35\x32\xdb\xe9\xd0\x01\x47\x44\xe9\x98\xe8\x60\xe1\x72\x4d\x97\x22\x2f\x88\xd2\x6f\x72\xc6\x4e\xf9\x12\xe6\x70\x3d\x54\xf6\xfb\x8c\xa9\x87\x70\x4e\x34\xbd\x84\xa1\xd2\xdf\x16\x5c\x3b\x3e\xa7\x2d\x9d\x38\x8e\x28\xb0\xd0\x46\x95\x67\x9d\x02\xd5\x2f\x0a\x0e\x4f\xbc\xb6\xf3\x57\x39\xd5\x15\x1a\x65\x6a\x38\xea\x40\xb9\x2b\x65\xf4\x76\xd0\x25\x61\x29\xe4\x09\xd4\xef\x1d\x43\x21\x12\x86\x39\x2b\x61\x86\x4e\x11\x61\x0a\x76\x6c\xf6\x15\x2b\x96\xf0\x57\x4a\x25\x64\xc7\xc3\xc9\x2a\xe1\x8e\x56\x4e\x2e\x20\x5b\x92\x63\xc3\x9b\x8e\xc4\x4e\xa4\x24\x37\x75\x5e\x8f\x29\x7f\xa5\x21\x36\x72\x03\xa6\xe5\x48\x23\xcf\xbb\x3d\x90\x6b\xd0\xf4\xc0\xd2\xd0\xa5\x9e\x6e\x28\x42\x18\xb3\x32\x48\xff\x0d\xed\xd8\x49\x4e\x62\x27\xb6\x7d\x09\xbd\xb5\x3b\xa6\xa3\xbd\x72\xce\x85\x60\x40\x78\xb7\xa0\x92\xb8\x27\x8e\x32\xea\xe3\xa0\x05\x23\x4b\xa6\xff\xd0\x5a\x6f\xa7\x17\x91\x06\xb4\x72\x17\x8e\x4a\x51\x33\x57\x24\xf6\x88\x66\x47\x50\x54\xcb\x9b\x40\xad\x09\x1b\xe0\x68\x1f\x2f\x3d\x96\x2c\x4c\xb6\xd6\x1c\xa4\x74\x01\xb6\x4d\x24\xe4\x61\xb5\x89\x00\x15\x10\x46\xe4\x26\x12\x34\x8d\x6d\xc7\x0f\xe2\x97\x10\xf5\xd9\xb7\x15\x5a\x1d\xc9\xc5\xaa\x7a\x30\xf0\x34\x36\x76\xb3\x5d\x17\xb5\x03\xdd\x4a\x51\x08\xe1\xac\xc2\x6e\x7e\xa7\xdc\xa0\x8f\x98\x20\xc6\x80\x8a\x09\x63\x16\xd1\x39\x9d\xdb\x23\x65\x24\x37\x86\x32\x17\x2a\x4d\xe2\x04\x9b\xe5\x1e\x76\x7a\xa2\x81\x9a\x0d\x2a\x68\x47\xae\x58\x95\xcf\x95\x90\x6d\x9d\xb1\xdd\x47\x4d\xae\x99\xef\x9c\xa9\x01\xbf\x2d\xdb\x0b\x18\x38\x4d\x07\x06\x31\x70\xdd\xcf\xf6\x8e\x8c\xb4\xc6\xf0\x6a\x19\xd3\xf2\x46\xa4\xde\xb1\xe9\x5d\x97\x87\x2a\x94\x0a\xf0\xaf\x40\x5f\x03\xbb\x09\xfb\x2a\x64\x6a\x90\xcf\x06\xd9\x6e\x19\x5c\xe7\xd7\x6d\xed\x75\xd7\x75\x8b\xf2\x90\x06\x44\x0b\xe9\x2d\xfe\xec\x84\xe1\x2c\x61\x3a\x10\xb2\x5a\xa1\x79\x6c\x2e\x37\xf0\x58\x2d\xf0\x56\x49\x92\x1a\xf9\x27\x14\x31\xa1\x46\x9a\x5a\x08\xa5\x8b\xc3\xba\x1e\x4b\x25\x6b\x7e\xe5\xa0\xcf\x48\x18\xca\xe6\x58\x1c\x3e\x36\xb2\xe4\x82\x3c\xb2\xbe\xff\xff\xf1\xcf\x46\x22\xbe\x52\x67\x44\xf2\xd6\x50\x10\x88\x94\xeb\x33\x1a\xda\x33\x94\x2b\x4d\x78\x00\x8e\x29\x4d\x8c\xac\xaf\x25\x29\xc8\xdc\x67\x4c\x75\x94\x6d\x0b\x6f\x75\xa2\x77\x43\x4e\x3d\xbf\x04\xae\x7f\xa7\xad\x9a\xd2\x5f\x07\x2e\xad\x73\xe4\x45\x75\xdb\x37\xd8\xdd\xf7\xe7\x75\xd5\x9c\x7d\x15\xae\xbb\x49\xcf\x52\xca\xf4\x98\x72\xb4\xb2\x08\x95\x6d\x86\x16\x8f\x59\x40\xe2\x43\x11\xc7\xa2\xcd\xa7\xda\x8c\xab\xd4\x23\xa3\x60\x7f\x7f\xff\x49\x96\x57\x52\x4e\xaf\xab\xbf\x67\xb1\x5a\x7d\x4c\xeb\x8f\x5c\xe1\xce\xdb\xf4\xed\x8d\x3e\x4c\x95\x16\xf1\x70\x93\x9f\xa2\xa0\xe6\x2c\x99\x10\xe5\x48\x69\x19\xe5\x43\x5c\x68\x92\x13\xb7\x24\x35\xda\x4c\xff\x3b\x21\x4f\xcf\x9f\x05\x87\x61\xf4\xf2\xd5\x45\xfc\x26\x39\xfe\x70\xf5\xe9\xfa\xe6\x8f\x2f\x9f\x67\xfe\xaa\x7b\x58\xfa\x1d\x19\x08\x32\x43\xa3\xaa\xd2\xb6\x15\x19\x8d\x6a\xc7\xc2\x34\x91\x73\x68\xe1\xb9\x6f\xd3\xee\x51\x6f\x07\x14\xcb\x98\xd7\x90\xca\x78\x57\xe3\xa8\x87\x23\x8c\x05\x16\x44\x95\x9c\xb3\xb5\x9e\xaa\x69\x3d\xee\xd2\x32\x05\xa7\xb7\x42\x60\x34\xa6\xda\xdf\xcb\xeb\x3c\xe3\x47\x99\xfd\xd3\xdc\x0b\xa8\x56\xb3\x14\x1c\x91\x94\xe5\x5b\x35\x72\x6f\x54\x20\x58\x1a\xfb\x3b\x25\x8e\xc3\xd2\xd5\x04\x40\x1d\xa7\x68\x67\xa0\x7a\xb6\xdd\xd7\x29\x52\x7f\xd2\xe4\x48\x42\x44\xed\xbe\xd7\x6d\xa0\xd5\x2c\x11\xe3\x44\xdf\x7c\xcc\x4a\xbf\x6f\xe8\x89\xb5\xd6\x6a\x49\xe3\xe3\x84\x04\xb7\x3b\x56\xe0\x3a\x21\x3c\x6c\xf5\x76\x50\xc7\x9d\x10\xae\xf5\x51\x1e\x34\xcf\x9b\xbc\xed\x60\xf4\x87\x59\xdd\x3c\x1d\x1a\x69\x15\x10\xd7\xc7\xd9\x3f\x18\x2d\x6b\x43\xdc\xea\xce\xfd\x08\xb4\x1f\x81\x76\xc7\x81\x56\x3f\x0e\x0c\x8d\xb0\xe2\x2d\x62\x7d\x7c\xb9\xde\x2c\xee\x72\x77\x3c\xdd\xe1\xea\xb5\xe4\xa8\x2c\x9e\xfe\x5b\x18\xdd\x28\x5a\xff\x4d\xf8\x7d\x6b\x3f\x2c\x39\xda\xca\xeb\x31\xea\x68\xe0\xfb\x5f\x63\x3b\xb4\x69\x3c\x87\x6d\x2b\x9c\xca\xcb\xc0\x6f\x99\xff\xb6\xfb\x2a\xb5\x37\x7e\x72\x36\xbb\xef\x7c\x93\x5a\x77\x5b\xf2\xe1\x6d\xf3\x07\xaa\xd1\xb7\x4b\x2c\x43\xd3\xfe\x77\x95\x40\xbe\x93\x24\xe1\xe1\xea\x11\x9c\x1e\x38\xb6\xaf\xb2\x96\xc7\xac\x57\x48\xfb\x18\x1a\xfe\x18\xb9\x0e\x34\x3f\xb9\x1c\xdc\x5b\x52\xe3\x5f\x83\x72\x05\xd1\x15\xd5\x0b\x94\x30\x12\xc0\x42\xb0\xac\x34\x35\xc8\x77\x03\x11\x97\xdd\x6f\xfc\x26\x55\x1a\x05\x82\x6b\x42\x39\x22\x1a\x31\x20\x4a\x23\xc1\xc1\xcf\xde\xec\x64\x4c\xa7\x5f\xa7\x53\x75\xff\xe4\x74\x39\x7b\x90\x7d\x98\x4e\x97\xeb\x5f\x8f\x06\x9b\x22\x52\x8d\x38\x5c\x31\xca\x41\xf9\x4d\x79\xc7\xd9\x0d\x22\x8c\x89\xab\x8a\x38\x33\x48\x2f\x00\x01\x0f\xbd\x26\x9c\x9e\x9c\x4e\xa7\x3c\xd3\x9e\xff\xba\xeb\x7d\xba\xda\xc9\x7e\x96\x3b\x7f\x07\x00\x00\xff\xff\x64\x4b\x14\x3b\xc1\x25\x00\x00")

func schemaJsonBytes() ([]byte, error) {
	return bindataRead(
		_schemaJson,
		"schema.json",
	)
}

func schemaJson() (*asset, error) {
	bytes, err := schemaJsonBytes()
	if err != nil {
		return nil, err
	}

	info := bindataFileInfo{name: "schema.json", size: 0, mode: os.FileMode(0), modTime: time.Unix(0, 0)}
	a := &asset{bytes: bytes, info: info}
	return a, nil
}

// Asset loads and returns the asset for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func Asset(name string) ([]byte, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("Asset %s can't read by error: %v", name, err)
		}
		return a.bytes, nil
	}
	return nil, fmt.Errorf("Asset %s not found", name)
}

// MustAsset is like Asset but panics when Asset would return an error.
// It simplifies safe initialization of global variables.
func MustAsset(name string) []byte {
	a, err := Asset(name)
	if err != nil {
		panic("asset: Asset(" + name + "): " + err.Error())
	}

	return a
}

// AssetInfo loads and returns the asset info for the given name.
// It returns an error if the asset could not be found or
// could not be loaded.
func AssetInfo(name string) (os.FileInfo, error) {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	if f, ok := _bindata[cannonicalName]; ok {
		a, err := f()
		if err != nil {
			return nil, fmt.Errorf("AssetInfo %s can't read by error: %v", name, err)
		}
		return a.info, nil
	}
	return nil, fmt.Errorf("AssetInfo %s not found", name)
}

// AssetNames returns the names of the assets.
func AssetNames() []string {
	names := make([]string, 0, len(_bindata))
	for name := range _bindata {
		names = append(names, name)
	}
	return names
}

// _bindata is a table, holding each asset generator, mapped to its name.
var _bindata = map[string]func() (*asset, error){
	"schema.json": schemaJson,
}

// AssetDir returns the file names below a certain
// directory embedded in the file by go-bindata.
// For example if you run go-bindata on data/... and data contains the
// following hierarchy:
//     data/
//       foo.txt
//       img/
//         a.png
//         b.png
// then AssetDir("data") would return []string{"foo.txt", "img"}
// AssetDir("data/img") would return []string{"a.png", "b.png"}
// AssetDir("foo.txt") and AssetDir("notexist") would return an error
// AssetDir("") will return []string{"data"}.
func AssetDir(name string) ([]string, error) {
	node := _bintree
	if len(name) != 0 {
		cannonicalName := strings.Replace(name, "\\", "/", -1)
		pathList := strings.Split(cannonicalName, "/")
		for _, p := range pathList {
			node = node.Children[p]
			if node == nil {
				return nil, fmt.Errorf("Asset %s not found", name)
			}
		}
	}
	if node.Func != nil {
		return nil, fmt.Errorf("Asset %s not found", name)
	}
	rv := make([]string, 0, len(node.Children))
	for childName := range node.Children {
		rv = append(rv, childName)
	}
	return rv, nil
}

type bintree struct {
	Func     func() (*asset, error)
	Children map[string]*bintree
}

var _bintree = &bintree{nil, map[string]*bintree{
	"schema.json": {schemaJson, map[string]*bintree{}},
}}

// RestoreAsset restores an asset under the given directory
func RestoreAsset(dir, name string) error {
	data, err := Asset(name)
	if err != nil {
		return err
	}
	info, err := AssetInfo(name)
	if err != nil {
		return err
	}
	err = os.MkdirAll(_filePath(dir, filepath.Dir(name)), os.FileMode(0755))
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(_filePath(dir, name), data, info.Mode())
	if err != nil {
		return err
	}
	err = os.Chtimes(_filePath(dir, name), info.ModTime(), info.ModTime())
	if err != nil {
		return err
	}
	return nil
}

// RestoreAssets restores an asset under the given directory recursively
func RestoreAssets(dir, name string) error {
	children, err := AssetDir(name)
	// File
	if err != nil {
		return RestoreAsset(dir, name)
	}
	// Dir
	for _, child := range children {
		err = RestoreAssets(dir, filepath.Join(name, child))
		if err != nil {
			return err
		}
	}
	return nil
}

func _filePath(dir, name string) string {
	cannonicalName := strings.Replace(name, "\\", "/", -1)
	return filepath.Join(append([]string{dir}, strings.Split(cannonicalName, "/")...)...)
}
