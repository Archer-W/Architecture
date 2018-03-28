#pragma once
/*!
 \file othello.h
 Describes the data structure *l-Othello*...
 */

#include <vector>
#include <iostream>
#include <array>
#include <queue>
#include <cstring>
#include <list>
#include "hash.h"
#include "disjointset.h"
#include <set>
#include <algorithm>
#include <cassert>

#include "../Simulation/othello_output.h"
using namespace std;

/*!
 * \brief Describes the data structure *l-Othello*. It classifies keys of *keyType* into *2^L* classes.
 * \note Query a key of keyType always return uint64_t, however, only the lowest L bits are meaningful. \n
 * The array are all stored in an array of uint64_t. There are actually m_a+m_b cells in this array, each of length L.
 * \note Be VERY careful!!!! valueType must be some kind of int with no more than 8 bytes' length
 */
template<class keyType,class valueType>
class Othello {
private:
  //*******builtin values
  const static int MAX_REHASH = 20; //!< Maximum number of rehash tries before report an error. If this limit is reached, Othello build fails.
  const static uint32_t L = sizeof(valueType) * 8; //!< the bit length of return value.
  const static uint64_t LMASK = ((L == 64) ? (~0ULL) : ((1ULL << L) - 1));

public:
    Othello(){
        
    }
  /*!
   \brief Construct *l-Othello*.
   \param [in] keyType *_keys, pointer to array of keys.
   \param [in] uint32_t keycount, number of keys, array size must match this.
   \param [in] bool _autoclear, clear memory used during construction once completed. Forbid future modification on the structure.
   \param [in] void * _values, Optional, pointer to array of values. When *_values* is empty, fill othello values such that the query result classifies keys to 2 sets. See more in notes.
   \param [in] _allowed_conflicts, default value is 10. during construction, Othello will remove at most this number of keys, instead of rehash.
   \note keycount should not exceed 2^29 for memory consideration.
   \n when *_values* is empty, classify keys into two sets X and Y, defined as follow: for each connected compoenents in G, select a node as the root, mark all edges in this connected compoenent as pointing away from the root. for all edges from U to V, query result is 1 (k in Y), for all edges from V to u, query result is 0 (k in X).
   */
  Othello(keyType *_keys, uint32_t keycount, valueType *_values) {
    keys = _keys;
    values = _values;

    resizeKey(keycount);
    resetBuildState();

    build();
  }

  //****************************************
  //*************DATA Plane
  //****************************************
private:
  vector<valueType> mem; //!< actual memory space for arrayA and arrayB.
  uint32_t ma = 0; //!< length of arrayA.
  uint32_t mb = 0; //!< length of arrayB
  uint32_t hashSizeReserve = 0;
  Hasher32<keyType> Ha; //<! hash function Ha
  Hasher32<keyType> Hb; //<! hash function Hb

  void inline get_hash_1(const keyType &k, uint32_t &ret1) {
    ret1 = (Ha)(k) & (ma - 1);
  }

  void inline get_hash_2(const keyType &v, uint32_t &ret1) {
    ret1 = (Hb)(v) & (mb - 1);
    ret1 += ma;
  }

  void inline get_hash(const keyType &v, uint32_t &ret1, uint32_t &ret2) {
    get_hash_1(v, ret1);
    get_hash_2(v, ret2);
  }

public:
  /*!
   \brief returns a 64-bit integer query value for a key.
   */
  inline valueType query(const keyType &k) {
    uint32_t ha, hb;
    return query(k, ha, hb);
  }

  /*!
   \brief compute the hash value of key and return query value.
   \param [in] keyType &k key
   \param [out] uint32_t &ha  computed hash function ha
   \param [out] uint32_t &hb  computed hash function hb
   \retval valueType
   */
  inline valueType query(const keyType &k, uint32_t &ha, uint32_t &hb) {
    get_hash_1(k, ha);
    valueType aa = mem[ha];
    get_hash_2(k, hb);
    valueType bb = mem[hb];
    ////printf("%llx   [%x] %x ^ [%x] %x = %x\n", k,ha,aa&LMASK,hb,bb&LMASK,(aa^bb)&LMASK);
    return LMASK & (aa ^ bb);
  }

  uint64_t reportDataPlaneMemUsage() {
    uint64_t size = hashSizeReserve * sizeof(valueType);
    cout << "Ma: " << ma * sizeof(valueType) << ", Mb" << mb * sizeof(valueType) << endl;

    return size;
  }

  //****************************************
  //*************CONTROL plane
  //****************************************
private:
  uint32_t keyCnt = 0, keyCntReserve = 0;
  // ******input of control plane
  keyType *keys;
  valueType *values;

  inline valueType randVal(int i = 0) {
    valueType v = rand();

    if (sizeof(valueType) > 4) {
      *(((int *) &v) + 1) = rand();
    }
    if (sizeof(valueType) > 8) {
      *(((int *) &v) + 2) = rand();
    }
    if (sizeof(valueType) > 12) {
      *(((int *) &v) + 3) = rand();
    }
    return v;
  }

  //! resize key and value related memory.
  //!
  //! Side effect: will change keyCnt, and if hash size is changed, will incur a rebuild
  void resizeKey(int keycount) {
    int hl1 = 1; //start from ma=64
    int hl2 = 1; //start from mb=64
    while ((1UL << hl2) < keycount * 1)
      hl2++;
    while ((1UL << hl1) < keycount * 1.333334)
      hl1++;
    ma = max(ma, (1U << hl1));
    mb = max(mb, (1U << hl2));

    if (keycount > keyCntReserve) {
      keyCntReserve = max(256, keycount * 2);
      nextKeyOfThisKeyAtPartA.resize(keyCntReserve);
      nextKeyOfThisKeyAtPartB.resize(keyCntReserve);
    }

    if (ma + mb > hashSizeReserve) {
      hashSizeReserve = (ma + mb) * 2;
      ma *= 2;
      mb *= 2;
      mem.resize(hashSizeReserve);
//      filled.resize(hashSizeReserve);
      free(filled);
      filled = (bool*) malloc(getFilledSize());
      keysOfThisNode.resize(hashSizeReserve);
      disj.resize(hashSizeReserve);

      build();
    }

    keyCnt = keycount;
  }

  void resetBuildState() {
    for (int i = 0; i < mem.size(); ++i) {
      mem[i] = randVal(i);
    }
    memset(filled, 0, getFilledSize());
//    fill(filled.begin(), filled.end(), false);
    fill(keysOfThisNode.begin(), keysOfThisNode.end(), -1);
    fill(nextKeyOfThisKeyAtPartA.begin(), nextKeyOfThisKeyAtPartA.end(), -1);
    fill(nextKeyOfThisKeyAtPartB.begin(), nextKeyOfThisKeyAtPartB.end(), -1);
    disj.reset();
  }

  bool built = false; //!< true if Othello is successfully built.
  uint32_t tryCount = 0; //!< number of rehash before a valid hash pair is found.
  /*! multiple keys may share a same end (hash value)
   first and next1, next2 maintain linked lists,
   each containing all keys with the same hash in either of their ends
   */
  vector<int32_t> keysOfThisNode;         //!< subscript: hashValue, value: keyIndex
  vector<int32_t> nextKeyOfThisKeyAtPartA;         //!< subscript: keyIndex, value: keyIndex
  vector<int32_t> nextKeyOfThisKeyAtPartB;         //! h2(keys[i]) = h2(keys[next2[i]]);

  DisjointSet disj;                     //!< store the hash values that are connected by key edges
//  uint64_t* filled = (uint64_t*) malloc(0);                  //!< remember filled nodes
//
//  inline void setFilled(int index) {
//    filled[index / 64] |= (1ULL << (index % 64));
//  }
//
//  inline void clearFilled(int index) {
//    filled[index / 64] &= ~(1ULL << (index % 64));
//  }
//
//  inline bool isFilled(int index) {
//    return filled[index / 64] & (1ULL << (index % 64));
//  }
//
//  inline int getFilledSize(int hashSize = 0) {
//    if (hashSize == 0) hashSize = hashSizeReserve;
//
//    return (hashSize + 63) / 64 * sizeof(*filled);
//  }

  bool* filled = (bool*) malloc(1);                  //!< remember filled nodes

  inline void setFilled(int index) {
    filled[index] = true;
  }

  inline void clearFilled(int index) {
    filled[index] = false;
  }

  inline bool isFilled(int index) {
    return filled[index];
  }

  inline int getFilledSize(int hashSize = 0) {
    if (hashSize == 0) hashSize = hashSizeReserve;

    return hashSize * sizeof(*filled);
  }

  //! gen new hash seed pair, cnt ++
  void newHash() {
    uint32_t s1 = rand();
    uint32_t s2 = rand();
#ifdef HASHSEED1
    s1 = HASHSEED1;
    s2 = HASHSEED2;
#endif
    Ha.setMaskSeed(ma - 1, s1);
    Hb.setMaskSeed(mb - 1, s2);
    tryCount++;
    if (tryCount > 1) {
      //printf("NewHash for the %d time\n", tryCount);
    }
  }

  //! update the disjoint set and the connected forest so that
  //! include all the old keys and the newly inserted key
  //! Warning: this method won't change the node value and the filled vector
  void addEdge(int key, uint32_t ha, uint32_t hb) {
    nextKeyOfThisKeyAtPartA[key] = keysOfThisNode[ha];
    keysOfThisNode[ha] = key;
    nextKeyOfThisKeyAtPartB[key] = keysOfThisNode[hb];
    keysOfThisNode[hb] = key;
    disj.merge(ha, hb);
  }

  //! test if this hash pair is acyclic, and build:
  //! the connected forest and the disjoint set of connected relation
  //! the disjoint set will be only useful to determine the root of a connected component
  //!
  //! Assume: all build related memory are cleared
  //! Side effect: the disjoint set and the connected forest are properly set
  bool testHash() {
    uint32_t ha, hb;
    for (int i = 0; i < keyCnt; i++) {
      get_hash(keys[i], ha, hb);
      if (disj.sameSet(ha, hb)) {  // if two indices are in the same disjoint set, means the corresponding key will incur circle.
        //printf("Conflict key %d: %llx\n", i, *(unsigned long long*) &(keys[i]));
        return false;
      }
      addEdge(i, ha, hb);
    }
    return true;
  }

  //! Fill a connected tree from the root.
  //! the value of root is set, and set all its children according to root values
  //! Assume: values are present, and the connected forest are properly set
  //! Side effect: all node in this tree is set and if updateToFilled, the filled vector will record filled values
  void fillTreeBFS(int root, bool updateToFilled) {
    if (updateToFilled) setFilled(root);

    list<uint32_t> Q;
    Q.clear();
    Q.push_back(root);

    std::set<uint32_t> visited;
    visited.insert(root);

    while (!Q.empty()) {
      uint32_t nodeid = (*Q.begin());
      Q.pop_front();

      // // find all the opposite side node to be filled

      // search all the edges of this node, to fill and enqueue the opposite side, and record the fill
      vector<int32_t> *nextKeyOfThisKey;
      nextKeyOfThisKey = (nodeid < ma) ? &nextKeyOfThisKeyAtPartA : &nextKeyOfThisKeyAtPartB;

      for (int32_t currKey = keysOfThisNode[nodeid]; currKey >= 0; currKey = nextKeyOfThisKey->at(currKey)) {
        uint32_t ha, hb;
        get_hash(keys[currKey], ha, hb);

        // now the opposite side node needs to be filled
        // fill and enqueue all next element of

        // ha xor hb must have been filled, find the opposite side
        bool aFilled = visited.find(ha) != visited.end();
        int toBeFilled = aFilled ? hb : ha;
        int hasBeenFilled = aFilled ? ha : hb;

        if (visited.find(toBeFilled) != visited.end()) {
          continue;
        }

        valueType value;
        valueType *loc = values + currKey;
        memcpy(&value, loc, sizeof(valueType));

        valueType valueToFill = value ^ mem[hasBeenFilled];
        mem[toBeFilled] = valueToFill;

        Q.push_back(toBeFilled);
        if (updateToFilled) setFilled(toBeFilled);
        visited.insert(toBeFilled);
      }
    }
  }

  //! Fill *Othello* so that the query returns values as defined
  //!
  //! Assume: edges and disjoint set are properly set up, filled is clear.
  //! Side effect: filled vector and all values are properly set
  void fillValue() {
    for (int i = 0; i < ma + mb; i++)
      if (disj.isRoot(i)) {  // we can only fix one end's value in a cc of keys, then fix the roots'
        mem[i] = randVal();
        fillTreeBFS(i, true);
      }
  }

  //! Begin a new build
  //!
  //! Side effect: 1) discard all memory except keys and values. 2) build fail, or
  //! all the values, filled vector, and disjoint set are properly set
  bool trybuild() {
    resetBuildState();

    if (keyCnt == 0) {
      return true;
    }

    bool succ;
    if ((succ = testHash())) {
      fillValue();
    }
    return succ;
  }

  //! try really hard to build, until success or tryCount >= MAX_REHASH
  //!
  //! Side effect: 1) discard all memory except keys and values. 2) build fail, or
  //! all the values, filled vector, and disjoint set are properly set
  bool build() {
    do {
      newHash();
      built = trybuild();
    } while ((!built) && (tryCount < MAX_REHASH));

    //printf("%08x %08x\n", Ha.s, Hb.s);
    if (built) {
      //cout << "Succ " << human(keyCnt) << " Keys, ma/mb = " << human(ma) << "/" << human(mb)    //
      //     << " keyT" << sizeof(keyType) * 8 << "b  valueT" << sizeof(valueType) * 8 << "b"     //
      //     << " L=" << (int) L << " After " << tryCount << "tries" << endl;
    } else {
      throw new exception();
    }

    return built;
  }

  bool testConnected(int32_t ha0, int32_t hb0) {
    list<int32_t> q;
    int t = keysOfThisNode[ha0];
    while (t >= 0) {
      q.push_back(t); //edges A -> B: >=0;  B -> A : <0;
      t = nextKeyOfThisKeyAtPartA[t];
    }

    while (!q.empty()) {
      int kid = q.front();
      bool isAtoB = (kid >= 0);
      if (kid < 0) kid = -kid - 1;
      q.pop_front();
      uint32_t ha, hb;
      get_hash(keys[kid], ha, hb);
      if (hb == hb0) return true;

      if (isAtoB) {
        int t = keysOfThisNode[hb];
        while (t >= 0) {
          if (t != kid) q.push_back(-t - 1);
          t = nextKeyOfThisKeyAtPartB[t];
        }
      } else {
        int t = keysOfThisNode[ha];
        while (t >= 0) {
          if (t != kid) q.push_back(t);
          t = nextKeyOfThisKeyAtPartA[t];
        }
      }
    }
    return false;
  }

public:
  uint32_t keySize() {
    return keyCnt;
  }

  /*!
   * \brief after putting some keys into *keys*, call this function to add keys into Othello.
   * values shall be stored in the array *values --> return true if succ.
   */
  bool keyAdded(int newkeys) {
    int start = keyCnt;
    resizeKey(keyCnt + newkeys);

    for (int i = start; i < keyCnt; i++) { // add keys one by one
      uint32_t ha, hb;
      get_hash(keys[i], ha, hb);

      assert(disj.sameSet(ha, hb) == testConnected(ha, hb));

      if (disj.sameSet(ha, hb)) {  // circle, rehash, tricky: takes all added keys together, rather than add one by one
        if (!build()) {
          keyCnt -= newkeys;
          throw new exception();
          return false;
        }
      } else {  // acyclic, just add
        addEdge(i, ha, hb);
        fillTreeBFS(ha, true);
      }
    }
    return true;
  }

  void updateValue(int index) {
      if (index >= keyCnt) throw exception();
      valueType v = values[index];
      uint32_t ha, hb;
      get_hash_1(keys[index], ha);
      fillTreeBFS(ha, false);
    }

  void updateKeyValue(int index, valueType value){
	  values[index] = value;
  }

};
