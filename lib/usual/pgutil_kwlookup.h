/* ANSI-C code produced by gperf version 3.1 */
/* Command-line: gperf -m5 usual/pgutil_kwlookup.g  */
/* Computed positions: -k'1-2,6,9,$' */

#if !((' ' == 32) && ('!' == 33) && ('"' == 34) && ('#' == 35) \
	&& ('%' == 37) && ('&' == 38) && ('\'' == 39) && ('(' == 40) \
	&& (')' == 41) && ('*' == 42) && ('+' == 43) && (',' == 44) \
	&& ('-' == 45) && ('.' == 46) && ('/' == 47) && ('0' == 48) \
	&& ('1' == 49) && ('2' == 50) && ('3' == 51) && ('4' == 52) \
	&& ('5' == 53) && ('6' == 54) && ('7' == 55) && ('8' == 56) \
	&& ('9' == 57) && (':' == 58) && (';' == 59) && ('<' == 60) \
	&& ('=' == 61) && ('>' == 62) && ('?' == 63) && ('A' == 65) \
	&& ('B' == 66) && ('C' == 67) && ('D' == 68) && ('E' == 69) \
	&& ('F' == 70) && ('G' == 71) && ('H' == 72) && ('I' == 73) \
	&& ('J' == 74) && ('K' == 75) && ('L' == 76) && ('M' == 77) \
	&& ('N' == 78) && ('O' == 79) && ('P' == 80) && ('Q' == 81) \
	&& ('R' == 82) && ('S' == 83) && ('T' == 84) && ('U' == 85) \
	&& ('V' == 86) && ('W' == 87) && ('X' == 88) && ('Y' == 89) \
	&& ('Z' == 90) && ('[' == 91) && ('\\' == 92) && (']' == 93) \
	&& ('^' == 94) && ('_' == 95) && ('a' == 97) && ('b' == 98) \
	&& ('c' == 99) && ('d' == 100) && ('e' == 101) && ('f' == 102) \
	&& ('g' == 103) && ('h' == 104) && ('i' == 105) && ('j' == 106) \
	&& ('k' == 107) && ('l' == 108) && ('m' == 109) && ('n' == 110) \
	&& ('o' == 111) && ('p' == 112) && ('q' == 113) && ('r' == 114) \
	&& ('s' == 115) && ('t' == 116) && ('u' == 117) && ('v' == 118) \
	&& ('w' == 119) && ('x' == 120) && ('y' == 121) && ('z' == 122) \
	&& ('{' == 123) && ('|' == 124) && ('}' == 125) && ('~' == 126))
/* The character set is not based on ISO-646.  */
#error "gperf generated tables don't work with this execution character set. Please report a bug to <bug-gperf@gnu.org>."
#endif

/* maximum key range = 296, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int pg_keyword_lookup_hash(register const char *str, register size_t len)
{
	static const unsigned short asso_values[] =
	{
		312, 312, 312, 312, 312, 312, 312, 312, 312, 312,
		312, 312, 312, 312, 312, 312, 312, 312, 312, 312,
		312, 312, 312, 312, 312, 312, 312, 312, 312, 312,
		312, 312, 312, 312, 312, 312, 312, 312, 312, 312,
		312, 312, 312, 312, 312, 312, 312, 312, 312, 312,
		312, 312, 312, 312, 312, 312, 312, 312, 312, 312,
		312, 312, 312, 312, 312, 312, 312, 312, 312, 312,
		312, 312, 312, 312, 312, 312, 312, 312, 312, 312,
		312, 312, 312, 312, 312, 312, 312, 312, 312, 312,
		312, 312, 312, 312, 312, 312, 312, 38, 125, 31,
		64, 10, 96, 60, 125, 26, 7, 5, 13, 63,
		10, 12, 70, 312, 5, 19, 3, 71, 131, 65,
		50, 77, 3, 312, 312, 312, 312, 312, 312, 312,
		312, 312, 312, 312, 312, 312, 312, 312, 312, 312,
		312, 312, 312, 312, 312, 312, 312, 312, 312, 312,
		312, 312, 312, 312, 312, 312, 312, 312, 312, 312,
		312, 312, 312, 312, 312, 312, 312, 312, 312, 312,
		312, 312, 312, 312, 312, 312, 312, 312, 312, 312,
		312, 312, 312, 312, 312, 312, 312, 312, 312, 312,
		312, 312, 312, 312, 312, 312, 312, 312, 312, 312,
		312, 312, 312, 312, 312, 312, 312, 312, 312, 312,
		312, 312, 312, 312, 312, 312, 312, 312, 312, 312,
		312, 312, 312, 312, 312, 312, 312, 312, 312, 312,
		312, 312, 312, 312, 312, 312, 312, 312, 312, 312,
		312, 312, 312, 312, 312, 312, 312, 312, 312, 312,
		312, 312, 312, 312, 312, 312
	};
	register unsigned int hval = len;

	switch (hval)
	{
	default:
		hval += asso_values[(unsigned char)str[8]];
	/*FALLTHROUGH*/
	case 8:
	case 7:
	case 6:
		hval += asso_values[(unsigned char)str[5]];
	/*FALLTHROUGH*/
	case 5:
	case 4:
	case 3:
	case 2:
		hval += asso_values[(unsigned char)str[1]];
	/*FALLTHROUGH*/
	case 1:
		hval += asso_values[(unsigned char)str[0]];
		break;
	}
	return hval + asso_values[(unsigned char)str[len - 1]];
}

const char *pg_keyword_lookup_real(register const char *str, register size_t len)
{
	enum {
		TOTAL_KEYWORDS = 148,
		MIN_WORD_LENGTH = 2,
		MAX_WORD_LENGTH = 17,
		MIN_HASH_VALUE = 16,
		MAX_HASH_VALUE = 311
	};

	struct pgkw_t {
		char pgkw_str16[sizeof("treat")];
		char pgkw_str22[sizeof("true")];
		char pgkw_str24[sizeof("or")];
		char pgkw_str27[sizeof("order")];
		char pgkw_str28[sizeof("not")];
		char pgkw_str29[sizeof("to")];
		char pgkw_str30[sizeof("left")];
		char pgkw_str31[sizeof("least")];
		char pgkw_str32[sizeof("real")];
		char pgkw_str33[sizeof("join")];
		char pgkw_str34[sizeof("on")];
		char pgkw_str36[sizeof("none")];
		char pgkw_str37[sizeof("else")];
		char pgkw_str39[sizeof("right")];
		char pgkw_str41[sizeof("select")];
		char pgkw_str42[sizeof("int")];
		char pgkw_str43[sizeof("time")];
		char pgkw_str44[sizeof("inout")];
		char pgkw_str45[sizeof("some")];
		char pgkw_str46[sizeof("inner")];
		char pgkw_str47[sizeof("limit")];
		char pgkw_str48[sizeof("in")];
		char pgkw_str51[sizeof("nchar")];
		char pgkw_str52[sizeof("into")];
		char pgkw_str53[sizeof("like")];
		char pgkw_str54[sizeof("ilike")];
		char pgkw_str55[sizeof("notnull")];
		char pgkw_str56[sizeof("table")];
		char pgkw_str57[sizeof("localtime")];
		char pgkw_str58[sizeof("integer")];
		char pgkw_str60[sizeof("cross")];
		char pgkw_str62[sizeof("create")];
		char pgkw_str63[sizeof("collate")];
		char pgkw_str64[sizeof("references")];
		char pgkw_str66[sizeof("is")];
		char pgkw_str67[sizeof("all")];
		char pgkw_str68[sizeof("analyze")];
		char pgkw_str69[sizeof("column")];
		char pgkw_str70[sizeof("intersect")];
		char pgkw_str71[sizeof("constraint")];
		char pgkw_str72[sizeof("except")];
		char pgkw_str73[sizeof("grant")];
		char pgkw_str75[sizeof("trim")];
		char pgkw_str76[sizeof("cast")];
		char pgkw_str77[sizeof("isnull")];
		char pgkw_str78[sizeof("as")];
		char pgkw_str79[sizeof("national")];
		char pgkw_str80[sizeof("coalesce")];
		char pgkw_str83[sizeof("case")];
		char pgkw_str84[sizeof("analyse")];
		char pgkw_str85[sizeof("row")];
		char pgkw_str86[sizeof("greatest")];
		char pgkw_str87[sizeof("end")];
		char pgkw_str88[sizeof("new")];
		char pgkw_str89[sizeof("out")];
		char pgkw_str90[sizeof("do")];
		char pgkw_str91[sizeof("asc")];
		char pgkw_str92[sizeof("old")];
		char pgkw_str93[sizeof("outer")];
		char pgkw_str95[sizeof("similar")];
		char pgkw_str96[sizeof("union")];
		char pgkw_str97[sizeof("default")];
		char pgkw_str98[sizeof("null")];
		char pgkw_str99[sizeof("user")];
		char pgkw_str100[sizeof("leading")];
		char pgkw_str101[sizeof("extract")];
		char pgkw_str102[sizeof("trailing")];
		char pgkw_str103[sizeof("only")];
		char pgkw_str104[sizeof("exists")];
		char pgkw_str106[sizeof("natural")];
		char pgkw_str107[sizeof("unique")];
		char pgkw_str108[sizeof("dec")];
		char pgkw_str109[sizeof("desc")];
		char pgkw_str111[sizeof("distinct")];
		char pgkw_str112[sizeof("deferrable")];
		char pgkw_str115[sizeof("and")];
		char pgkw_str116[sizeof("for")];
		char pgkw_str117[sizeof("float")];
		char pgkw_str119[sizeof("smallint")];
		char pgkw_str120[sizeof("offset")];
		char pgkw_str122[sizeof("localtimestamp")];
		char pgkw_str123[sizeof("precision")];
		char pgkw_str125[sizeof("array")];
		char pgkw_str126[sizeof("position")];
		char pgkw_str127[sizeof("freeze")];
		char pgkw_str128[sizeof("any")];
		char pgkw_str129[sizeof("session_user")];
		char pgkw_str130[sizeof("setof")];
		char pgkw_str132[sizeof("decimal")];
		char pgkw_str133[sizeof("xmlforest")];
		char pgkw_str134[sizeof("asymmetric")];
		char pgkw_str135[sizeof("xmlroot")];
		char pgkw_str136[sizeof("xmlparse")];
		char pgkw_str137[sizeof("current_time")];
		char pgkw_str138[sizeof("xmlconcat")];
		char pgkw_str139[sizeof("current_role")];
		char pgkw_str140[sizeof("group")];
		char pgkw_str142[sizeof("then")];
		char pgkw_str144[sizeof("xmlpi")];
		char pgkw_str145[sizeof("numeric")];
		char pgkw_str146[sizeof("xmlelement")];
		char pgkw_str147[sizeof("concurrently")];
		char pgkw_str149[sizeof("false")];
		char pgkw_str152[sizeof("over")];
		char pgkw_str153[sizeof("xmlserialize")];
		char pgkw_str154[sizeof("returning")];
		char pgkw_str155[sizeof("using")];
		char pgkw_str157[sizeof("bit")];
		char pgkw_str160[sizeof("placing")];
		char pgkw_str162[sizeof("between")];
		char pgkw_str163[sizeof("bigint")];
		char pgkw_str164[sizeof("primary")];
		char pgkw_str165[sizeof("char")];
		char pgkw_str166[sizeof("check")];
		char pgkw_str168[sizeof("from")];
		char pgkw_str170[sizeof("symmetric")];
		char pgkw_str175[sizeof("authorization")];
		char pgkw_str177[sizeof("verbose")];
		char pgkw_str181[sizeof("timestamp")];
		char pgkw_str183[sizeof("current_schema")];
		char pgkw_str184[sizeof("full")];
		char pgkw_str185[sizeof("foreign")];
		char pgkw_str186[sizeof("xmlexists")];
		char pgkw_str188[sizeof("interval")];
		char pgkw_str192[sizeof("boolean")];
		char pgkw_str198[sizeof("current_date")];
		char pgkw_str200[sizeof("current_user")];
		char pgkw_str202[sizeof("current_timestamp")];
		char pgkw_str204[sizeof("when")];
		char pgkw_str205[sizeof("where")];
		char pgkw_str206[sizeof("character")];
		char pgkw_str207[sizeof("off")];
		char pgkw_str208[sizeof("overlaps")];
		char pgkw_str213[sizeof("values")];
		char pgkw_str218[sizeof("current_catalog")];
		char pgkw_str219[sizeof("varchar")];
		char pgkw_str220[sizeof("with")];
		char pgkw_str224[sizeof("substring")];
		char pgkw_str227[sizeof("window")];
		char pgkw_str236[sizeof("fetch")];
		char pgkw_str237[sizeof("initially")];
		char pgkw_str265[sizeof("overlay")];
		char pgkw_str266[sizeof("both")];
		char pgkw_str272[sizeof("variadic")];
		char pgkw_str273[sizeof("xmlattributes")];
		char pgkw_str279[sizeof("nullif")];
		char pgkw_str289[sizeof("having")];
		char pgkw_str311[sizeof("binary")];
	};
	static const struct pgkw_t pgkw_contents =
	{
		"treat",
		"true",
		"or",
		"order",
		"not",
		"to",
		"left",
		"least",
		"real",
		"join",
		"on",
		"none",
		"else",
		"right",
		"select",
		"int",
		"time",
		"inout",
		"some",
		"inner",
		"limit",
		"in",
		"nchar",
		"into",
		"like",
		"ilike",
		"notnull",
		"table",
		"localtime",
		"integer",
		"cross",
		"create",
		"collate",
		"references",
		"is",
		"all",
		"analyze",
		"column",
		"intersect",
		"constraint",
		"except",
		"grant",
		"trim",
		"cast",
		"isnull",
		"as",
		"national",
		"coalesce",
		"case",
		"analyse",
		"row",
		"greatest",
		"end",
		"new",
		"out",
		"do",
		"asc",
		"old",
		"outer",
		"similar",
		"union",
		"default",
		"null",
		"user",
		"leading",
		"extract",
		"trailing",
		"only",
		"exists",
		"natural",
		"unique",
		"dec",
		"desc",
		"distinct",
		"deferrable",
		"and",
		"for",
		"float",
		"smallint",
		"offset",
		"localtimestamp",
		"precision",
		"array",
		"position",
		"freeze",
		"any",
		"session_user",
		"setof",
		"decimal",
		"xmlforest",
		"asymmetric",
		"xmlroot",
		"xmlparse",
		"current_time",
		"xmlconcat",
		"current_role",
		"group",
		"then",
		"xmlpi",
		"numeric",
		"xmlelement",
		"concurrently",
		"false",
		"over",
		"xmlserialize",
		"returning",
		"using",
		"bit",
		"placing",
		"between",
		"bigint",
		"primary",
		"char",
		"check",
		"from",
		"symmetric",
		"authorization",
		"verbose",
		"timestamp",
		"current_schema",
		"full",
		"foreign",
		"xmlexists",
		"interval",
		"boolean",
		"current_date",
		"current_user",
		"current_timestamp",
		"when",
		"where",
		"character",
		"off",
		"overlaps",
		"values",
		"current_catalog",
		"varchar",
		"with",
		"substring",
		"window",
		"fetch",
		"initially",
		"overlay",
		"both",
		"variadic",
		"xmlattributes",
		"nullif",
		"having",
		"binary"
	};
  #define pgkw ((const char *) &pgkw_contents)
	static const int wordlist[] =
	{
		-1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str16,
		-1, -1, -1, -1, -1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str22,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str24,
		-1, -1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str27,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str28,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str29,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str30,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str31,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str32,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str33,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str34,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str36,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str37,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str39,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str41,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str42,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str43,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str44,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str45,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str46,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str47,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str48,
		-1, -1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str51,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str52,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str53,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str54,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str55,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str56,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str57,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str58,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str60,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str62,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str63,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str64,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str66,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str67,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str68,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str69,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str70,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str71,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str72,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str73,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str75,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str76,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str77,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str78,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str79,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str80,
		-1, -1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str83,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str84,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str85,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str86,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str87,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str88,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str89,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str90,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str91,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str92,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str93,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str95,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str96,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str97,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str98,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str99,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str100,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str101,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str102,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str103,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str104,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str106,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str107,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str108,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str109,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str111,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str112,
		-1, -1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str115,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str116,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str117,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str119,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str120,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str122,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str123,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str125,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str126,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str127,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str128,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str129,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str130,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str132,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str133,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str134,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str135,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str136,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str137,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str138,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str139,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str140,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str142,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str144,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str145,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str146,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str147,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str149,
		-1, -1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str152,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str153,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str154,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str155,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str157,
		-1, -1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str160,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str162,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str163,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str164,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str165,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str166,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str168,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str170,
		-1, -1, -1, -1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str175,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str177,
		-1, -1, -1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str181,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str183,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str184,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str185,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str186,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str188,
		-1, -1, -1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str192,
		-1, -1, -1, -1, -1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str198,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str200,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str202,
		-1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str204,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str205,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str206,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str207,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str208,
		-1, -1, -1, -1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str213,
		-1, -1, -1, -1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str218,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str219,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str220,
		-1, -1, -1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str224,
		-1, -1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str227,
		-1, -1, -1, -1, -1, -1, -1, -1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str236,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str237,
		-1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str265,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str266,
		-1, -1, -1, -1, -1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str272,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str273,
		-1, -1, -1, -1, -1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str279,
		-1, -1, -1, -1, -1, -1, -1, -1, -1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str289,
		-1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1,
		(int)(size_t)&((struct pgkw_t *)0)->pgkw_str311
	};

	if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH) {
		register unsigned int key = pg_keyword_lookup_hash (str, len);

		if (key <= MAX_HASH_VALUE) {
			register int o = wordlist[key];
			if (o >= 0) {
				register const char *s = o + pgkw;

				if (*str == *s && !strcmp (str + 1, s + 1))
					return s;
			}
		}
	}
	return 0;
}
