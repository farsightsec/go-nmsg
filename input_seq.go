/*
 * Copyright (c) 2018 by Farsight Security, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

package nmsg

import (
	"container/list"
	"time"
)

type seqCacheEntry struct {
	lastUsed time.Time
	seqid    uint64
	nextSeq  uint32
}

type seqCache struct {
	expiry time.Duration
	idmap  map[uint64]*list.Element
	lru    *list.List
}

func newSequenceCache(expiry time.Duration) *seqCache {
	return &seqCache{
		expiry: expiry,
		idmap:  make(map[uint64]*list.Element),
		lru:    list.New(),
	}
}

const maxDrop = 1048576

func (sc *seqCache) Update(n *Nmsg) (missed int) {
	if n.Sequence == nil || n.SequenceId == nil {
		return
	}
	seqid := n.GetSequenceId()
	lruent, ok := sc.idmap[seqid]
	if !ok {
		sc.idmap[seqid] = sc.lru.PushBack(
			&seqCacheEntry{
				lastUsed: time.Now(),
				seqid:    seqid,
				nextSeq:  n.GetSequence() + 1,
			})
		return 0
	}
	seq := n.GetSequence()
	ent := lruent.Value.(*seqCacheEntry)

	ent.lastUsed = time.Now()
	sc.lru.MoveToBack(lruent)

	if seq == ent.nextSeq {
		ent.nextSeq++
		return 0
	}

	if seq > ent.nextSeq {
		if seq-ent.nextSeq < maxDrop {
			missed = int(seq - ent.nextSeq)
		}
		ent.nextSeq = seq + 1
		return missed
	}

	delta := int64(int64(seq) + (1 << 32) - int64(ent.nextSeq))
	if delta < maxDrop {
		missed = int(delta)
	}

	ent.nextSeq = seq + 1
	return missed
}

func (sc *seqCache) Expire() {
	for sc.lru.Len() > 0 {
		lruent := sc.lru.Front()
		ent := lruent.Value.(*seqCacheEntry)
		if time.Since(ent.lastUsed) <= sc.expiry {
			break
		}
		sc.lru.Remove(lruent)
		delete(sc.idmap, ent.seqid)
	}
}
