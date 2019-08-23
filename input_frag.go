/*
 * Copyright (c) 2018 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package nmsg

// NMSG Fragment Cache.

import (
	"bytes"
	"container/list"
	"sort"
	"time"
)

type fragCacheEntry struct {
	lastUsed time.Time
	id       uint32
	frags    fragList
}

// fragList implements sort.Interface to support sorting fragments on
// their "Current" field prior to reassembly.
type fragList []*NmsgFragment

func (fl fragList) Len() int           { return len(fl) }
func (fl fragList) Less(i, j int) bool { return fl[i].GetCurrent() < fl[j].GetCurrent() }
func (fl fragList) Swap(i, j int)      { fl[i], fl[j] = fl[j], fl[i] }

type fragCache struct {
	expiry time.Duration
	idmap  map[uint32]*list.Element
	lru    *list.List
}

func newFragmentCache(expiry time.Duration) *fragCache {
	return &fragCache{
		expiry: expiry,
		idmap:  make(map[uint32]*list.Element),
		lru:    list.New(),
	}
}

// Expire too-old entries from the fragment cache, returning the number
// of incomplete containers and fragments dropped.
func (fc *fragCache) Expire() (containers, frags int) {
	for fc.lru.Len() > 0 {
		lruent := fc.lru.Front()
		ent := lruent.Value.(*fragCacheEntry)
		if time.Since(ent.lastUsed) <= fc.expiry {
			break
		}
		containers++
		frags += len(ent.frags)
		fc.lru.Remove(lruent)
		delete(fc.idmap, ent.id)
	}
	return
}

// Inserts a fragment into the cache. If the fragment completes a fragmented
// container, Insert returns the reassembled container body. Otherwise, returns
// nil.
func (fc *fragCache) Insert(f *NmsgFragment) []byte {
	id := f.GetId()
	lruent, ok := fc.idmap[id]
	if !ok {
		fc.idmap[id] = fc.lru.PushBack(
			&fragCacheEntry{
				lastUsed: time.Now(),
				id:       id,
				frags:    fragList{f},
			})
		return nil
	}

	ent := lruent.Value.(*fragCacheEntry)
	for i := range ent.frags {
		if ent.frags[i].GetCurrent() == f.GetCurrent() {
			/* duplicate fragment */
			return nil
		}
	}
	ent.frags = append(ent.frags, f)
	if ent.frags.Len() <= int(f.GetLast()) {
		ent.lastUsed = time.Now()
		fc.lru.MoveToBack(lruent)
		return nil
	}
	fc.lru.Remove(lruent)
	delete(fc.idmap, id)

	/* sort and reassemble fragments */
	sort.Sort(ent.frags)
	var b bytes.Buffer
	for i := range ent.frags {
		b.Write(ent.frags[i].GetFragment())
	}
	return b.Bytes()
}
