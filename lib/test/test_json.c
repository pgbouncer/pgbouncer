#include <usual/json.h>

#include <usual/string.h>
#include "test_common.h"

static const char *simple_value(const char *json)
{
	struct JsonContext *ctx;
	struct JsonValue *obj;
	static char buf[128];
	const char *res;

	ctx = json_new_context(NULL, 128);
	obj = json_parse(ctx, json, strlen(json));
	if (!obj) {
		snprintf(buf, sizeof(buf), "EPARSE: %s", json_strerror(ctx));
		json_free_context(ctx);
		return buf;
	} else if (json_value_is_null(obj)) {
		res = "NULL";
	} else if (json_value_is_bool(obj)) {
		bool val;
		if (!json_value_as_bool(obj, &val)) {
			res = "EBOOL";
		} else {
			res = val ? "TRUE" : "FALSE";
		}
	} else if (json_value_is_int(obj)) {
		int64_t val;
		if (!json_value_as_int(obj, &val)) {
			res = "ELONG";
		} else {
			snprintf(buf, sizeof(buf), "INT:%" PRId64, val);
			res = buf;
		}
	} else if (json_value_is_float(obj)) {
		double val;
		int i, j;
		if (!json_value_as_float(obj, &val)) {
			res = "EDBL";
		} else {
			snprintf(buf, sizeof(buf), "FLOAT:%.17g", val);
			for (i = 0; buf[i]; i++) {
				if (!buf[i]) break;
				if (buf[i] >= '0' && buf[i] <= '9') continue;
				if (buf[i] == '+' || buf[i] == '-') continue;
				if (buf[i] == 'e' || buf[i] == 'E') continue;
				if (buf[i] == '.') continue;
				if (buf[i] == ',') buf[i] = '.';
				else if (buf[i] & 0x80) {
					j = i;
					while (buf[j] & 0x80) j++;
					buf[i++] = '.';
					memmove(buf + i, buf + j, strlen(buf + j) + 1);
				}
			}
			res = buf;
		}
	} else if (json_value_is_string(obj)) {
		const char *val;
		if (!json_value_as_string(obj, &val, NULL)) {
			res = "ESTR";
		} else {
			snprintf(buf, sizeof(buf), "STR:%s", val);
			res = buf;
		}
	} else {
		res = "ENOSIMPLE";
	}
	json_free_context(ctx);
	return res;
}

static const char *rerender_opts(const char *json, int opts)
{
	struct JsonContext *ctx;
	struct JsonValue *obj;
	static char buf[1024];
	struct MBuf dst;

	memset(buf, 0, sizeof buf);
	mbuf_init_fixed_writer(&dst, buf, sizeof(buf));

	ctx = json_new_context(NULL, 128);
	json_set_options(ctx, opts);
	obj = json_parse(ctx, json, strlen(json));
	if (!obj) {
		snprintf(buf, sizeof(buf), "EPARSE: %s", json_strerror(ctx));
		json_free_context(ctx);
		return buf;
	}
	if (!json_render(&dst, obj))
		return "ERENDER";
	if (!mbuf_write_byte(&dst, 0))
		return "ENUL";
	json_free_context(ctx);
	return buf;
}

static const char *xrerender_opts(const char *xjson, int opts)
{
	static char buf[1024];
	char *s;
	const char *res;

	memset(buf, 0, sizeof buf);
	strlcpy(buf, xjson, sizeof(buf));
	for (s = buf; *s; s++) {
		if (*s == '|')
			*s = '\\';
		else if (*s == '\'')
			*s = '"';
	}

	res = rerender_opts(buf, opts);

	strlcpy(buf, res, sizeof(buf));
	for (s = buf; *s; s++) {
		if (*s == '\\')
			*s = '|';
		else if (*s == '"')
			*s = '\'';
	}
	return buf;
}

static const char *rerender(const char *json)
{
	return rerender_opts(json, 0);
}

static const char *xrerender(const char *xjson)
{
	return xrerender_opts(xjson, 0);
}

static void test_json_basic(void *p)
{
	str_check(simple_value("1"), "INT:1");
	str_check(simple_value("  10000 "), "INT:10000");
	str_check(simple_value("true"), "TRUE");
	str_check(simple_value(" true "), "TRUE");
	str_check(simple_value("false"), "FALSE");
	str_check(simple_value(" false "), "FALSE");
	str_check(simple_value("null"), "NULL");
	str_check(simple_value(" null "), "NULL");
	str_check(simple_value("1.5"), "FLOAT:1.5");
	str_check(simple_value(" 1.5 "), "FLOAT:1.5");
	str_check(simple_value("\"abc\""), "STR:abc");
	str_check(simple_value("\"\""), "STR:");
	str_check(simple_value(" \"qq\\\"zz\\\\qq\" "), "STR:qq\"zz\\qq");

	str_check(rerender("1"), "1");
	str_check(rerender("[]"), "[]");
	str_check(rerender("[1]"), "[1]");
	str_check(rerender("[null, true, false]"), "[null,true,false]");
	str_check(rerender("[1,2,[3,[],[4]]]"), "[1,2,[3,[],[4]]]");
	str_check(rerender("[\"\", \"a\", \"\\\"\", \"a\\\"b\"]"), "[\"\",\"a\",\"\\\"\",\"a\\\"b\"]");

	str_check(rerender("{}"), "{}");
	str_check(rerender("{\"key\": \"val\"}"), "{\"key\":\"val\"}");
	str_check(xrerender("{'key': 'val|'qqq'}"), "{'key':'val|'qqq'}");
	str_check(xrerender("{'k': [1,2,-3], 'k2': {}}"), "{'k':[1,2,-3],'k2':{}}");

	str_check(xrerender("'|b|f|n|r|t|/'"), "'|b|f|n|r|t/'");
	str_check(xrerender("'|a'"), "EPARSE: Line #1: Invalid escape code");

	str_check(xrerender("'𝄞'"), "'𝄞'");
	str_check(xrerender("'|u0034'"), "'4'");
	str_check(xrerender("'|u003'"), "EPARSE: Line #1: Invalid hex escape");
	str_check(xrerender("'|u'"), "EPARSE: Line #1: Invalid hex escape");
	str_check(xrerender("'|uD834|uDD1E'"), "'𝄞'");
	str_check(xrerender("'|uD834 |uDD1E'"), "EPARSE: Line #1: Invalid UTF16 escape");
	str_check(xrerender("'|uD834|uD834'"), "EPARSE: Line #1: Invalid UTF16 escape");
	str_check(xrerender("'|uD834|u0100'"), "EPARSE: Line #1: Invalid UTF16 escape");
	str_check(xrerender("'|uD834|uF000'"), "EPARSE: Line #1: Invalid UTF16 escape");
	str_check(xrerender("'|uDD34|uDD00'"), "EPARSE: Line #1: Invalid UTF16 escape");
	str_check(xrerender("'|uD834'"), "EPARSE: Line #1: Invalid UTF16 escape");

	// check for \u2028 \u2029 special handling
	{
		const char utfesc[] = {'\'', 0xe2, 0x80, 0xa7, '|', 'u', '2', '0', '2', '8', '|', 'u', '2', '0', '2', '9', 0xe2, 0x80, 0xaa, '\'', 0};
		str_check(xrerender("'|u2027|u2028|u2029|u202a'"), utfesc);
	}

	str_check(xrerender("["), "EPARSE: Line #1: Container still open");
	str_check(xrerender("[{"), "EPARSE: Line #1: Container still open");
	str_check(xrerender("\""), "EPARSE: Line #1: Unexpected end of string");
	str_check(xrerender("[\""), "EPARSE: Line #1: Unexpected end of string");
	str_check(xrerender("[,"), "EPARSE: Line #1: Unexpected symbol: ','");
	str_check(xrerender("[]]"), "EPARSE: Line #1: Unexpected symbol: ']'");
	str_check(xrerender("tr"), "EPARSE: Line #1: Unexpected end of token");
	str_check(xrerender("treu"), "EPARSE: Line #1: Invalid token");
	str_check(xrerender("999999999999999999999999"), "EPARSE: Line #1: Number parse failed");
	str_check(xrerender("99999999999999999999999999999999999999999999999999999999999999999999"), "EPARSE: Line #1: Number parse failed");
	str_check(xrerender("99.999.999"), "EPARSE: Line #1: Number parse failed");
	str_check(xrerender("[\n\"ln\n\","), "EPARSE: Line #3: Container still open");
	str_check(xrerender("!"), "EPARSE: Line #1: Invalid symbol: '!'");

	{
	const char badenc1[] = {'"', 0xc1, 0xbf, '"', 0};
	const char badenc2[] = {'"', 0xe0, 0x9f, 0xbf, '"', 0};
	const char badenc3[] = {'"', 0xf0, 0x8f, 0xbf, 0xbf, '"'};
	const char badenc4[] = {'"', 0xf4, 0x90, 0x80, 0x80, '"', 0};

	str_check(xrerender(badenc1), "EPARSE: Line #1: Invalid UTF8 sequence");
	str_check(xrerender(badenc2), "EPARSE: Line #1: Invalid UTF8 sequence");
	str_check(xrerender(badenc3), "EPARSE: Line #1: Invalid UTF8 sequence");
	str_check(xrerender(badenc4), "EPARSE: Line #1: Invalid UTF8 sequence");
	}
end:;
}

static const char *render(struct JsonValue *obj)
{
	static char buf[1024];
	struct MBuf dst;
	mbuf_init_fixed_writer(&dst, buf, sizeof(buf));
	if (!json_render(&dst, obj))
		return "ERENDER";
	if (!mbuf_write_byte(&dst, 0))
		return "EMEM";
	return buf;
}

static void test_json_render(void *p)
{
	struct JsonContext *ctx;
	struct JsonValue *list, *dict;

	ctx = json_new_context(NULL, 128);
	tt_assert(ctx);

	list = json_new_list(ctx);
	tt_assert(json_list_append(list, json_new_null(ctx)));
	tt_assert(json_list_append(list, json_new_bool(ctx, 1)));
	tt_assert(json_list_append(list, json_new_bool(ctx, 0)));
	tt_assert(json_list_append(list, json_new_int(ctx, 600)));
	tt_assert(json_list_append(list, json_new_float(ctx, -0.5)));
	tt_assert(json_list_append(list, json_new_string(ctx, "q\\we")));

	str_check(render(list), "[null,true,false,600,-0.5,\"q\\\\we\"]");

	dict = json_new_dict(ctx);
	tt_assert(dict);
	str_check(render(dict), "{}");
	tt_assert(json_dict_put(dict, "k", json_new_list(ctx)));
	str_check(render(dict), "{\"k\":[]}");
	tt_assert(json_dict_put_null(dict, "n"));
	tt_assert(json_dict_put_bool(dict, "b", 1));
	tt_assert(json_dict_put_int(dict, "i", 22));
	tt_assert(json_dict_put_float(dict, "f", 1));
	tt_assert(json_dict_put_string(dict, "s", "qwe"));
	str_check(render(dict), "{\"b\":true,\"f\":1.0,\"i\":22,\"k\":[],\"n\":null,\"s\":\"qwe\"}");

	str_check(render(json_new_string(ctx, "\"\\ low:\a\b\f\n\r\t")), "\"\\\"\\\\ low:\\u0007\\b\\f\\n\\r\\t\"");

	list = json_new_list(ctx);
	tt_assert(json_list_append_null(list));
	tt_assert(json_list_append_bool(list, false));
	tt_assert(json_list_append_int(list, -1));
	tt_assert(json_list_append_float(list, -2));
	tt_assert(json_list_append_string(list, "qz\0foo"));
	str_check(render(list), "[null,false,-1,-2.0,\"qz\"]");

	json_free_context(ctx);
end:;
}

static void test_json_fetch(void *p)
{
	struct JsonContext *ctx;
	struct JsonValue *list, *dict, *dict2, *obj;
	const char *json = "{\"intk\": 16, \"fk\": 1.1, \"sk\": \"qwe\", \"tk\": true, \"nk\": null, \"lst\":[], \"obj\": {}}";
	bool bval;
	const char *sval;
	size_t slen;
	int64_t ival;
	double fval;

	ctx = json_new_context(NULL, 128);
	tt_assert(ctx);
	dict = json_parse(ctx, json, strlen(json));
	tt_assert(dict);

	bval = false;
	tt_assert(json_dict_get_bool(dict, "tk", &bval)); tt_assert(bval == true);
	tt_assert(!json_dict_get_bool(dict, "nk", &bval)); tt_assert(bval == true);
	tt_assert(!json_dict_get_bool(dict, "missing", &bval)); tt_assert(bval == true);
	tt_assert(json_dict_get_opt_bool(dict, "nk", &bval)); tt_assert(bval == true);
	tt_assert(json_dict_get_opt_bool(dict, "missing", &bval)); tt_assert(bval == true);
	tt_assert(!json_dict_get_opt_bool(dict, "sk", &bval)); tt_assert(bval == true);

	ival = 8;
	tt_assert(json_dict_get_int(dict, "intk", &ival)); tt_assert(ival == 16);
	tt_assert(!json_dict_get_int(dict, "nk", &ival)); tt_assert(ival == 16);
	tt_assert(!json_dict_get_int(dict, "missing", &ival)); tt_assert(ival == 16);
	tt_assert(json_dict_get_opt_int(dict, "nk", &ival)); tt_assert(ival == 16);
	tt_assert(json_dict_get_opt_int(dict, "missing", &ival)); tt_assert(ival == 16);
	tt_assert(!json_dict_get_opt_int(dict, "sk", &ival)); tt_assert(ival == 16);

	fval = -9;
	tt_assert(json_dict_get_float(dict, "fk", &fval)); tt_assert(fval == 1.1);
	tt_assert(!json_dict_get_float(dict, "nk", &fval)); tt_assert(fval == 1.1);
	tt_assert(!json_dict_get_float(dict, "missing", &fval)); tt_assert(fval == 1.1);
	fval = -7;
	tt_assert(json_dict_get_opt_float(dict, "fk", &fval)); tt_assert(fval == 1.1);
	tt_assert(json_dict_get_opt_float(dict, "missing", &fval)); tt_assert(fval == 1.1);
	tt_assert(!json_dict_get_opt_float(dict, "obj", &fval)); tt_assert(fval == 1.1);

	sval = "x"; slen = 1;
	tt_assert(json_dict_get_string(dict, "sk", &sval, NULL)); str_check(sval, "qwe");
	tt_assert(json_dict_get_string(dict, "sk", &sval, &slen)); tt_assert(slen == 3);
	tt_assert(!json_dict_get_string(dict, "nk", &sval, &slen)); str_check(sval, "qwe");
	tt_assert(!json_dict_get_string(dict, "missing", &sval, NULL)); str_check(sval, "qwe");
	sval = "z"; slen = 1;
	tt_assert(json_dict_get_opt_string(dict, "sk", &sval, NULL)); str_check(sval, "qwe");
	tt_assert(json_dict_get_opt_string(dict, "sk", &sval, &slen)); tt_assert(slen == 3);
	tt_assert(json_dict_get_opt_string(dict, "missing", &sval, NULL)); str_check(sval, "qwe");
	tt_assert(!json_dict_get_opt_string(dict, "fk", &sval, NULL)); str_check(sval, "qwe");

	list = NULL;
	tt_assert(!json_dict_get_list(dict, "sk", &list)); tt_assert(list == NULL);
	tt_assert(json_dict_get_list(dict, "lst", &list)); tt_assert(list);
	tt_assert(json_value_type(list) == JSON_LIST);
	list = NULL;
	tt_assert(!json_dict_get_opt_list(dict, "fk", &list)); tt_assert(!list);
	tt_assert(json_dict_get_opt_list(dict, "lst", &list)); tt_assert(list);
	tt_assert(json_value_type(list) == JSON_LIST);
	tt_assert(json_dict_get_opt_list(dict, "nk", &list)); tt_assert(list);
	tt_assert(json_value_type(list) == JSON_LIST);

	dict2 = NULL;
	tt_assert(!json_dict_get_dict(dict, "sk", &dict2)); tt_assert(dict2 == NULL);
	tt_assert(json_dict_get_dict(dict, "obj", &dict2)); tt_assert(dict2);
	tt_assert(json_value_type(dict2) == JSON_DICT);
	dict2 = NULL;
	tt_assert(!json_dict_get_opt_dict(dict, "fk", &dict2)); tt_assert(!dict2);
	tt_assert(json_dict_get_opt_dict(dict, "obj", &dict2)); tt_assert(dict2);
	tt_assert(json_value_type(dict2) == JSON_DICT);
	tt_assert(json_dict_get_opt_dict(dict, "nk", &dict2)); tt_assert(dict2);
	tt_assert(json_value_type(dict2) == JSON_DICT);

	obj = NULL;
	tt_assert(!json_dict_get_value(dict, "missing", &obj)); tt_assert(obj == NULL);
	tt_assert(json_dict_get_value(dict, "nk", &obj));
	tt_assert(obj); tt_assert(json_value_type(obj) == JSON_NULL);
	tt_assert(json_dict_get_value(dict, "obj", &obj));
	tt_assert(obj); tt_assert(json_value_type(obj) == JSON_DICT);
end:
	json_free_context(ctx);
}

static bool dict_walker(void *arg, struct JsonValue *key, struct JsonValue *val)
{
	const char *k;
	int64_t v;
	int *counter = arg;

	if (!json_value_as_string(key, &k, NULL))
		return false;
	if (!json_value_as_int(val, &v))
		return false;
	if (atol(k) != v)
		return false;
	if (v != (*counter)++)
		return false;
	return true;
}

static bool list_walker(void *arg, struct JsonValue *elem)
{
	int64_t v;
	int *counter = arg;

	if (!json_value_as_int(elem, &v))
		return false;
	if (v != (*counter)++)
		return false;
	return true;
}

static void test_json_iter(void *p)
{
	struct JsonContext *ctx;
	struct JsonValue *list, *dict;
	const char *json = "{\"3\": 3, \"1\": 1, \"2\": 2}";
	const char *json2 = "[1,2,3]";
	int counter;

	ctx = json_new_context(NULL, 128); tt_assert(ctx);
	dict = json_parse(ctx, json, strlen(json)); tt_assert(dict);
	int_check(json_value_size(dict), 3);
	counter = 1;
	tt_assert(json_dict_iter(dict, dict_walker, &counter));

	list = json_parse(ctx, json2, strlen(json2)); tt_assert(list);
	int_check(json_value_size(list), 3);
	counter = 1;
	tt_assert(json_list_iter(list, list_walker, &counter));
end:
	json_free_context(ctx);
}

static void test_json_relax(void *p)
{
	int rlx = JSON_PARSE_RELAXED;
	/* comments */
	str_check(xrerender_opts("/* */ { 'a': 3 } // ", rlx), "{'a':3}");
	str_check(xrerender_opts("// \n { //\n'a': 3//zzz\n} //", rlx), "{'a':3}");
	str_check(xrerender_opts("/*\n/**/ { /**/ 'a': 3/*\n*/} /**/", rlx), "{'a':3}");
	str_check(xrerender_opts("/* */ { 'a': [,], 'b':{,},'c':[1,],} // ", rlx), "{'a':[],'b':{},'c':[1]}");
	/* extra comma */
	str_check(xrerender_opts("[,,]", rlx), "EPARSE: Line #1: Unexpected symbol: ','");
	str_check(xrerender_opts("[1,,]", 0), "EPARSE: Line #1: Unexpected symbol: ','");
	str_check(xrerender_opts("[1,,]", rlx), "EPARSE: Line #1: Unexpected symbol: ','");
	str_check(xrerender_opts("[1,,1]", rlx), "EPARSE: Line #1: Unexpected symbol: ','");
	str_check(xrerender_opts("[],", rlx), "EPARSE: Line #1: Unexpected symbol: ','");
	str_check(xrerender_opts("{,,}", rlx), "EPARSE: Line #1: Unexpected symbol: ','");
	str_check(xrerender_opts("{},", rlx), "EPARSE: Line #1: Unexpected symbol: ','");
	str_check(xrerender_opts("{'a':1,,},", rlx), "EPARSE: Line #1: Unexpected symbol: ','");
	str_check(xrerender_opts("{'a':1,,'b':2},", rlx), "EPARSE: Line #1: Unexpected symbol: ','");
end:;
}

struct testcase_t json_tests[] = {
	{ "basic", test_json_basic },
	{ "render", test_json_render },
	{ "fetch", test_json_fetch },
	{ "iter", test_json_iter },
	{ "relax", test_json_relax },
	END_OF_TESTCASES
};
