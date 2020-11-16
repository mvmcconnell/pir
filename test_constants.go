package pir

// test configuration parameters
const TestDBHeight = 1 << 5
const TestDBSize = 1 << 10

const BenchmarkDBHeight = 1 << 5
const BenchmarkDBSize = 1 << 10

const MinGroupSize = 1
const MaxGroupSize = 5
const SlotBytes = 3
const SlotBytesStep = 5
const NumProcsForQuery = 4 // number of parallel processors
const NumQueries = 50      // number of queries to run

const StatisticalSecurityParam = 32 // 32 bits of stat sec
