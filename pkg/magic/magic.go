package magic

import (
	"strings"
)

/*
0	string/t	@
>1	string/cW	\ echo\ off	DOS batch file text
!:mime	text/x-msdos-batch
!:ext	bat
>1	string/cW	echo\ off	DOS batch file text
!:mime	text/x-msdos-batch
!:ext	bat
>1	string/cW	rem		DOS batch file text
!:mime	text/x-msdos-batch
!:ext	bat
>1	string/cW	set\ 		DOS batch file text
!:mime	text/x-msdos-batch
!:ext	bat
*/

func Extension(data string) string {
	if ExeFile(data) {
		return "exe"
	}
	if BatFile(data) {
		return "bat"
	}
	return ""
}

func BatFile(data string) bool {
	firstLine := true
	n := 0
	for _, line := range strings.Split(strings.ReplaceAll(data, "\r\n", "\n"), "\n") {
		line = strings.ToLower(line)
		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if firstLine {
			switch line {
			case "echo off":
				return true
			case "@echo off":
				return true
			}
			firstLine = false
		}
		if strings.HasPrefix(line, "set ") {
			n++
		}
		if strings.HasPrefix(line, "rem ") {
			n++
		}
		if strings.HasPrefix(line, "setlocal ") {
			n += 2
		}
		if strings.HasPrefix(line, "call ") {
			n++
		}
		if strings.Contains(line, "errorlevel") {
			n++
		}
		if strings.HasPrefix(line, "goto ") {
			n++
		}
		//	if strings.HasPrefix(line, ":") {
		//		n++
		//	}
		if n > 3 {
			return true
		}
	}
	return false
}

func ExeFile(data string) bool {
	return strings.HasPrefix(data, "MZ")
}
