1.在filter.cpp里面
根据输入的字符串构造filters对象来判断是否打印当前事件，最重要的就是
70行的下面
sinsp_filter_check_list::sinsp_filter_check_list()
{
	//////////////////////////////////////////////////////////////////////////////
	// ADD NEW FILTER CHECK CLASSES HERE
	//////////////////////////////////////////////////////////////////////////////
	add_filter_check(new sinsp_filter_check_fd());
	add_filter_check(new sinsp_filter_check_thread());
	add_filter_check(new sinsp_filter_check_event());
	add_filter_check(new sinsp_filter_check_user());
	add_filter_check(new sinsp_filter_check_group());
	add_filter_check(new sinsp_filter_check_syslog());
	add_filter_check(new sinsp_filter_check_container());
	add_filter_check(new sinsp_filter_check_utils());
	add_filter_check(new sinsp_filter_check_fdlist());
#ifndef CYGWING_AGENT
	add_filter_check(new sinsp_filter_check_k8s());
	add_filter_check(new sinsp_filter_check_mesos());
#endif
	add_filter_check(new sinsp_filter_check_tracer());
	add_filter_check(new sinsp_filter_check_evtin());
}

m_filter的初始化
sinsp_filter_compiler::sinsp_filter_compiler(sinsp* inspector, const string& fltstr, bool ttable_only)
{
	m_inspector = inspector;
	m_ttable_only = ttable_only;
	m_scanpos = -1;
	m_scansize = 0;
	m_state = ST_NEED_EXPRESSION;
	m_filter = new sinsp_filter(m_inspector);
	m_last_boolop = BO_NONE;
	m_nest_level = 0;
	m_fltstr = fltstr;
}

sinsp_filter::sinsp_filter(sinsp *inspector)
{
	m_inspector = inspector;
}

class SINSP_PUBLIC sinsp_filter : public gen_event_filter

bool gen_event_filter::run(gen_event *evt)
{
	bool tmp = m_filter->compare(evt);
	return tmp;
}

gen_event_filter::gen_event_filter()
{
	// cout << "created: " << this << endl;
	m_filter = new gen_event_filter_expression();
	m_curexpr = m_filter;
}



bool gen_event_filter_expression::compare(gen_event *evt)
{
	uint32_t j;
	uint32_t size = (uint32_t)m_checks.size();
	bool res = true;
	gen_event_filter_check* chk = NULL;
	for(j = 0; j < size; j++)
	{
		chk = m_checks[j];
		ASSERT(chk != NULL);
		if(j == 0)
		{
			switch(chk->m_boolop)
			{
			case BO_NONE:
				res = chk->compare(evt);
				if (res) {
					evt->set_check_id(chk->get_check_id());
				}
				break;
			case BO_NOT:
				res = !chk->compare(evt);
				break;
			default:
				ASSERT(false);
				break;
			}
		}
		else
		{
			switch(chk->m_boolop)
			{
			case BO_OR:
				if(res)
				{
					goto done;
				}
				res = chk->compare(evt);
				if (res) {
					evt->set_check_id(chk->get_check_id());
				}
				break;
			case BO_AND:
				if(!res)
				{
					goto done;
				}
				res = chk->compare(evt);
				if (res) {
					evt->set_check_id(chk->get_check_id());
				}
				break;
			case BO_ORNOT:
				if(res)
				{
					goto done;
				}
				res = !chk->compare(evt);
				if (res) {
					evt->set_check_id(chk->get_check_id());
				}
				break;
			case BO_ANDNOT:
				if(!res)
				{
					goto done;
				}
				res = !chk->compare(evt);
				if (res) {
					evt->set_check_id(chk->get_check_id());
				}
				break;
			default:
				ASSERT(false);
				break;
			}
		}
	}
 done:
	return res;
}

bool sinsp_filter_check::compare(sinsp_evt *evt)
{
	uint32_t evt_val_len=0;
	bool sanitize_strings = false;
	uint8_t* extracted_val = extract(evt, &evt_val_len, sanitize_strings);

	if(extracted_val == NULL)
	{
		return false;
	}

	bool tmp = flt_compare(m_cmpop,
			   m_info.m_fields[m_field_id].m_type,
			   extracted_val,
			   evt_val_len,
			   m_val_storage_len);
	return tmp;
}

以sinsp_filter_check_container为例,
uint8_t* sinsp_filter_check_container::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{
  ......
  	case TYPE_CONTAINER_NAME:
		if(tinfo->m_container_id.empty())
		{
			m_tstr = "host";
		}
		else
		{
			const sinsp_container_info *container_info =
				m_inspector->m_container_manager.get_container(tinfo->m_container_id);
			if(!container_info)
			{
				return NULL;
			}

			if(container_info->m_name.empty())
			{
				return NULL;
			}

			m_tstr = container_info->m_name;
		}

		RETURN_EXTRACT_STRING(m_tstr);
  ......
}

最后
#ifdef HAS_CHISELS
		if(!g_chisels.empty())
		{
			for(vector<sinsp_chisel*>::iterator it = g_chisels.begin(); it != g_chisels.end(); ++it)
			{
				bool tmp = (*it)->run(ev);
				if(!tmp)
				{
					continue;
				}
			}
		}
    
run:
bool sinsp_chisel::run(sinsp_evt* evt)
{

#ifdef HAS_LUA_CHISELS
	string line;

	ASSERT(m_ls);
	//
	// Make the event available to the API
	//
	lua_pushlightuserdata(m_ls, evt);
	lua_setglobal(m_ls, "sievt"); //注意这里的sievt，以后还会用到的

	//
	// If there is a timeout callback, see if it's time to call it
	//
	do_timeout(evt);

	//
	// If there is a filter, run it
	//
	if(m_lua_cinfo->m_filter != NULL)
	{
		bool tmp = m_lua_cinfo->m_filter->run(evt);
		if (!tmp)
		{
			return false;
		}
	}

	if (evt->get_type() == PPME_SYSCALL_EXECVE_19_X)
		cout << "in chisel.cpp, after m_lua_cinfo" << endl;

	//
	// If the script has the on_event callback, call it
	//

	if(m_lua_has_handle_evt)
	{
		lua_getglobal(m_ls, "on_event");
		if(lua_pcall(m_ls, 0, 1, 0) != 0)
		{
			throw sinsp_exception(m_filename + " chisel error: " + lua_tostring(m_ls, -1));
		}

		int oeres = lua_toboolean(m_ls, -1);
		lua_pop(m_ls, 1);

		if(m_lua_cinfo->m_end_capture == true)
		{
			throw sinsp_capture_interrupt_exception();
		}

		if(oeres == false)
		{
			return false;
		}
	}

	//
	// If the script has a formatter, run it
	//
	if(m_lua_cinfo->m_formatter != NULL)
	{
		if(m_lua_cinfo->m_formatter->tostring(evt, &line))
		{
			cout << line << endl;
		}
	}
	return true;
#endif
}
最难理解的是m_lua_cinfo->m_filter->run(evt);
m_lua_cinfo在chisel.cpp中的void sinsp_chisel::load(string cmdstr)中被定义

luaL_openlib(m_ls, "chisel", ll_chisel, 0);
......
m_lua_cinfo = new chiselinfo(m_inspector);
......
lua_pushlightuserdata(m_ls, this); // the object itself
lua_setglobal(m_ls, "sichisel"); // object is defined as "sichisel"

在spy_users.lua中
chisel.set_filter("((evt.type=execve and evt.dir=<) or 
(evt.type=chdir and evt.dir=< and proc.name contains sh and not proc.name contains sshd)) and evt.failed=false")

set_filter
int lua_cbacks::set_filter(lua_State *ls)
{
	lua_getglobal(ls, "sichisel");

	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	const char* filter = lua_tostring(ls, 1);

	ASSERT(ch);
	ASSERT(ch->m_lua_cinfo);

	try
	{
		ch->m_lua_cinfo->set_filter(filter);
	}
	catch(sinsp_exception& e)
	{
		string err = "invalid filter in chisel " + ch->m_filename + ": " + e.what();
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("chisel error");
	}

	return 0;
}


最后就是我们喜闻乐见的打印环节了
function on_init()
  ......
  fuser = chisel.request_field("user.name")
  ......

function on_event()
  ......
  local user = evt.field(fuser)
  ......
	
	

让我们先来看看chisel.request_filed("user.name")

	int lua_cbacks::request_field(lua_State *ls)
{
	lua_getglobal(ls, "sichisel");

	sinsp_chisel* ch = (sinsp_chisel*)lua_touserdata(ls, -1);
	lua_pop(ls, 1);

	sinsp* inspector = ch->m_inspector;

	const char* fld = lua_tostring(ls, 1);
	// cout << fld << endl;
	if(fld == NULL)
	{
		string err = "chisel requesting nil field";
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("chisel error");
	}

	sinsp_filter_check* chk = g_filterlist.new_filter_check_from_fldname(fld,
		inspector,
		false);

	if(chk == NULL)
	{
		string err = "chisel requesting nonexistent field " + string(fld);
		fprintf(stderr, "%s\n", err.c_str());
		throw sinsp_exception("chisel error");
	}

	chk->parse_field_name(fld, true, false);

	lua_pushlightuserdata(ls, chk);

	ch->m_allocated_fltchecks.push_back(chk);

	return 1;
}

最后是把chk压入了栈顶,所以fuser实际上是	s
insp_filter_check* chk = g_filterlist.new_filter_check_from_fldname(fld, inspector, false);
