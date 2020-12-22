package pir

// test configuration parameters
const TestDBHeight = 1 << 5
const TestDBSize = 1 << 10

const BenchmarkDBHeight = 1 << 10
const BenchmarkDBSize = 1 << 20

const MinGroupSize = 1
const MaxGroupSize = 5
const SlotBytes = 3
const SlotBytesStep = 5
const NumProcsForQuery = 4         // number of parallel processors
const NumQueries = 50              // number of queries to run
const StatisticalSecurityBytes = 8 // 8 bytes of stat sec
