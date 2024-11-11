// This is pretty much the simplest possible server that works as a LAN cache
// for Steam, allowing you to automatically archive the raw CDN data for every
// game you download. Just run it (it'll bind to port 80) in the directory you
// want content to be saved in, and tell Steam to connect to the server by
// setting lancache.steamcontent.com to the IP of the server in your hosts.
// Do not use this as a general-purpose caching server; it doesn't check if
// local caches are up-to-date (this is fine for Steam because its CDN files
// have different URLS for different versions.)
package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

type fileLock struct {
	mutex		sync.Mutex
	refCountMutex	sync.Mutex
	count		int
}

var lockedFiles map[string]*fileLock
var mapLock sync.Mutex

func main() {
	lockedFiles = make(map[string]*fileLock)
	manifestTrailingFive := regexp.MustCompile("\\/5(\\/\\d+)?$")
	fmt.Println(http.ListenAndServe("0.0.0.0:80", http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		mapLock.Lock()
		lock, locked := lockedFiles[r.URL.Path]
		mapLock.Unlock()
		if locked && lock != nil {
			fmt.Println("getting lock for " + r.URL.Path)
			lock.refCountMutex.Lock()
			lock.count++
			lock.refCountMutex.Unlock()
			lock.mutex.Lock()
			lock.refCountMutex.Lock()
			lock.count--
			lock.refCountMutex.Unlock()
		} else {
			fmt.Println("creating lock for " + r.URL.Path)
			lock = &fileLock{}
			mapLock.Lock()
			lockedFiles[r.URL.Path] = lock
			mapLock.Unlock()
			lock.mutex.Lock()
		}
		fmt.Println("obtained lock on " + r.URL.Path)
		defer func() {
			lock.refCountMutex.Lock()
			if lock.count == 0 {
				mapLock.Lock()
				lockedFiles[r.URL.Path] = nil
				mapLock.Unlock()
				fmt.Println("destroyed lock on " + r.URL.Path)
			} else {
				lock.mutex.Unlock()
				fmt.Println("released lock on " + r.URL.Path)
				lock.refCountMutex.Unlock()
			}
		}()

		if r.Host == "" || r.Host == "127.0.0.1" {
			rw.WriteHeader(400)
			rw.Write([]byte("Missing host header.\n"))
			return
		} else if r.URL.Path == "/favicon.ico" {
			rw.WriteHeader(404)
			return
		} else {
			cwd, e := os.Getwd()
			if e != nil {
				fmt.Println("can't get cwd: " + e.Error())
				rw.WriteHeader(500)
				return
			}
			urlPath := r.URL.Path
			urlPath = strings.ReplaceAll(urlPath, "/depot", "/depots")
			urlPath = strings.ReplaceAll(urlPath, "/chunk", "")
			if strings.Contains(urlPath, "manifest") {
				orig := urlPath
				urlPath = strings.ReplaceAll(urlPath, "/manifest", "")
				urlPath = manifestTrailingFive.ReplaceAllString(urlPath, "")
				urlPath += ".zip"
				fmt.Println("transformed manifest path from " + orig + " to " + urlPath)
			}
			cachePath := cwd + filepath.Join("/", urlPath)
			file, e := os.Open(cachePath)
			if e == nil {
				defer file.Close()
				io.Copy(rw, file)
				fmt.Println("served from cache: " + cachePath)
			} else {
				fmt.Println("downloading from CDN: " + r.Host)
				resp, e := http.Get("http://" + r.Host + r.URL.Path)
				if e == nil {
					rw.WriteHeader(resp.StatusCode)
					if resp.StatusCode != 200 {
						return
					}
					if e = os.MkdirAll(filepath.Dir(cachePath), os.ModePerm); e != nil {
						fmt.Println("failed to create directories: " + e.Error())
						io.Copy(rw, resp.Body)
						return
					}
					file, e := os.Create(cachePath)
					if e != nil {
						fmt.Println("can't cache file " + cachePath + ": " + e.Error())
						io.Copy(rw, resp.Body)
					} else {
						io.Copy(file, resp.Body)
						file.Close()
						// check if the connection was cancelled
						info, e := os.Stat(cachePath)
						if e != nil {
							fmt.Println("couldn't stat cached file: " + e.Error())
						} else if info.Size() != resp.ContentLength {
							fmt.Println("wrong length (transfer interrupted?) for file " + cachePath)
							if e = os.Remove(cachePath); e != nil {
								fmt.Println("couldn't delete corrupt file: " + e.Error())
							}
						} else {
							fmt.Println("cached: " + cachePath)
							file, e := os.Open(cachePath)
							if e != nil {
								fmt.Println("couldn't re-read cached file: " + e.Error())
							}
							io.Copy(rw, file)
						}
					}
				} else {
					fmt.Println(e)
					rw.WriteHeader(500)
					return
				}
			}
		}
	})))
}
