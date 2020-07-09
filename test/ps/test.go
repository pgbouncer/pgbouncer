package main

import (
	"database/sql"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	_ "github.com/lib/pq"
)

// Test Prepared Statements from lib/pq

func check(e error) {
	if e != nil {
		msg := fmt.Sprintf("Error: %v", e)
		panic(msg)
	}
}

func assertEqInt(actual, expected int) {
	if actual != expected {
		panic(fmt.Sprintf("(actual) %v != %v (expected)", actual, expected))
	}
}

func assertEqString(actual, expected string) {
	if actual != expected {
		panic(fmt.Sprintf("(actual) %v != %v (expected)", actual, expected))
	}
}

func checkExec(db *sql.DB, sql string, args ...interface{}) {
	_, err := db.Exec(sql, args...)
	check(err)
}

func setupDB(db *sql.DB) {
	// Create two tables with different column orders (and diferent column types), so that
	// if our prepared statements get swapped around, we'll detect it.
	checkExec(db, "CREATE TABLE IF NOT EXISTS autotx_a (iv INT, tv TEXT)")
	checkExec(db, "CREATE TABLE IF NOT EXISTS autotx_b (tv TEXT, iv INT)")
	checkExec(db, "TRUNCATE autotx_a")
	checkExec(db, "TRUNCATE autotx_b")
	checkExec(db, "INSERT INTO autotx_a (iv, tv) VALUES ($1,$2)", 2, "two")
	checkExec(db, "INSERT INTO autotx_a (iv, tv) VALUES ($1,$2)", 4, "four")
	checkExec(db, "INSERT INTO autotx_b (tv, iv) VALUES ($1,$2)", "seven", 7)
	checkExec(db, "INSERT INTO autotx_b (tv, iv) VALUES ($1,$2)", "nine", 9)
}

func onceOff(db *sql.DB) {
	iv := 0
	param := 0
	db.QueryRow("SELECT iv,$1 FROM autotx_a ORDER BY iv LIMIT 1", 5).Scan(&iv, &param)
	assertEqInt(iv, 2)
	assertEqInt(param, 5)
}

func start(testname string) {
	fmt.Printf("*** %v ***\n", testname)
}

func testSimpleStatements(db *sql.DB) {
	// These blocks of code are useful when doing protocol analysis (ie in combination with the pgbouncer setting log_event_stream)
	start("Simple anonymous prepared statement executed twice")
	onceOff(db)
	onceOff(db)
}

func testParseFail(db *sql.DB) {
	start("Parse fail")
	iv := 0
	param := 0
	err := db.QueryRow("SELECT foo,$1 FROM notexist", 5).Scan(&iv, &param)
	fmt.Printf("(Expected parse to fail) - failure message: %v\n", err)
	// Verify that a subsequent query succeeds
	onceOff(db)
}

func testSingleExplicitPS(db *sql.DB) {
	start("Single explicit prepared statement")
	st, err := db.Prepare("SELECT iv FROM autotx_a WHERE tv = $1")
	check(err)
	defer st.Close()
	iv := 0
	err = st.QueryRow("two").Scan(&iv)
	check(err)
	assertEqInt(iv, 2)
	err = st.QueryRow("four").Scan(&iv)
	check(err)
	assertEqInt(iv, 4)
}

func testDualExplicitPS(db *sql.DB) {
	start("Dual explicit prepared statement")
	st1, err := db.Prepare("SELECT iv FROM autotx_a WHERE tv = $1")
	check(err)
	st2, err := db.Prepare("SELECT tv FROM autotx_b WHERE iv = $1")
	check(err)

	iv := 0
	err = st1.QueryRow("two").Scan(&iv)
	check(err)
	assertEqInt(iv, 2)

	tv := ""
	err = st2.QueryRow(7).Scan(&tv)
	check(err)
	assertEqString(tv, "seven")

	st1.Close()
	st2.Close()
}

func testConcurrentStatements(db *sql.DB) {
	start("Concurrent anonymous statements")

	totalExecuted := int64(0)
	stop := int64(0)
	exited := make(chan bool)
	testSeconds := 2
	nThreads := 5

	poll := func(threadIdx int) {
		ticker := 0
		for {
			//fmt.Printf("%v:%v\n", threadIdx, ticker)
			iv := 0
			tv := ""
			param := 0
			err := db.QueryRow("SELECT iv,tv,$1 FROM autotx_a ORDER BY iv LIMIT 1", 5).Scan(&iv, &tv, &param)
			check(err)
			assertEqInt(iv, 2)

			iv = 0
			err = db.QueryRow("SELECT tv,iv,$1 FROM autotx_b ORDER BY iv LIMIT 1", 5).Scan(&tv, &iv, &param)
			check(err)
			assertEqInt(iv, 7)

			atomic.AddInt64(&totalExecuted, 1)
			ticker++
			if atomic.LoadInt64(&stop) == 1 {
				break
			}
		}
		exited <- true
	}

	for i := 0; i < nThreads; i++ {
		go poll(i)
	}

	for i := 0; i < testSeconds; i++ {
		time.Sleep(time.Second)
	}

	atomic.StoreInt64(&stop, 1)

	for i := 0; i < nThreads; i++ {
		<-exited
	}

	fmt.Printf("Executed %v statements\n", totalExecuted)
}

func main() {
	// Set native to true to execute the tests directly against Postgres,
	// which is useful when doing a sense check against the tests in here.
	//
	// An easy way to craft new tests is to set native = true, then add
	// your test code, and make sure it's working. Then, set native = false,
	// and ensure that you still get the same behaviour when running through
	// pgbouncer.
	native := false

	conStr := "host=localhost port=6432 user=postgres password=kama dbname=postgres sslmode=disable"
	if native {
		strings.Replace(conStr, "6432", "5432", -1)
	}
	db, err := sql.Open("postgres", conStr)
	check(err)

	setupDB(db)

	testParseFail(db)
	testSingleExplicitPS(db)
	testDualExplicitPS(db)
	testSimpleStatements(db)
	testConcurrentStatements(db)
}
