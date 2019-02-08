## Object.create Type-Confusion
* CVE-2018-17463
* Object.create has side-effect but wrong assumption makes type-confusion in optimization phase
* Make arbitrary read/write primitives via value overlapping using above type confusion vulnerability
* Current exploit is not reliable
