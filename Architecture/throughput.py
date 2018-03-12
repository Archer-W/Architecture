#! /usr/bin/python
from gensim.models.word2vec import Word2Vec
import time
import sys

def word2vec_multicore_train(path):
    length = int(sys.argv[1])
    workers_num = int(sys.argv[2])
    index = 0
    start_time = time.time()
    cont=[]
    contents=[]
    for line in open(path,'r').readlines():
        line_content = line.split()
        cont.append(line_content)
        index +=1
    for i in range(length):
        for j in range(index):
            contents.append(cont[j])

    stop_time = time.time()
    #print(stop_time-start_time)
   # print(len(contents))
    word2vec = Word2Vec(contents,workers=workers_num)
    #print(word2vec['materi'])
    word2vec_stop_time = time.time()
    print(word2vec_stop_time-stop_time)

if __name__ == '__main__':
    word2vec_multicore_train('acm.txt')
