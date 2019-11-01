1.关于PPME_SYSCALL_EXECVE_19_E和PPME_SYSCALL_EXECVE_19_X

struct ppm_event_info {
	char name[PPM_MAX_NAME_LEN]; /**< Name. */
	enum ppm_event_category category; /**< Event category, e.g. 'file', 'net', etc. */
	enum ppm_event_flags flags; /**< flags for this event. */
	uint32_t nparams; /**< Number of parameter in the params array. */
	struct ppm_param_info params[PPM_MAX_EVENT_PARAMS]; /**< parameters descriptions. */
} _packed;

struct ppm_param_info {
	char name[PPM_MAX_NAME_LEN];  /**< Parameter name, e.g. 'size'. */
	enum ppm_param_type type; /**< Parameter type, e.g. 'uint16', 'string'... */
	enum ppm_print_format fmt; /**< If this is a numeric parameter, this flag specifies if it should be rendered as decimal or hex. */
	const void *info; /**< If this is a flags parameter, it points to an array of ppm_name_value,
			       else if this is a dynamic parameter it points to an array of ppm_param_info */
	uint8_t ninfo; /**< Number of entry in the info array. */
} _packed;


const struct ppm_event_info g_event_info[PPM_EVENT_MAX] = {
    ......
/* PPME_SYSCALL_EXECVE_19_E */
    {
        "execve", 
        EC_PROCESS, 
        EF_MODIFIES_STATE, 
        1, 
        {
            {
            "filename", 
            PT_FSPATH, 
            PF_NA
            }
        } 
    }
    ......
    /* PPME_SYSCALL_EXECVE_19_X */
    {
    "execve", 
    EC_PROCESS, 
    EF_MODIFIES_STATE, 
    19, 
        {
            {"res", PT_ERRNO, PF_DEC}, 
            {"exe", PT_CHARBUF, PF_NA}, 
            {"args", PT_BYTEBUF, PF_NA}, 
            {"tid", PT_PID, PF_DEC}, 
            {"pid", PT_PID, PF_DEC}, 
            {"ptid", PT_PID, PF_DEC}, 
            {"cwd", PT_CHARBUF, PF_NA}, 
            {"fdlimit", PT_UINT64, PF_DEC}, 
            {"pgft_maj", PT_UINT64, PF_DEC}, 
            {"pgft_min", PT_UINT64, PF_DEC}, 
            {"vm_size", PT_UINT32, PF_DEC}, 
            {"vm_rss", PT_UINT32, PF_DEC}, 
            {"vm_swap", PT_UINT32, PF_DEC}, 
            {"comm", PT_CHARBUF, PF_NA}, 
            {"cgroups", PT_BYTEBUF, PF_NA}, 
            {"env", PT_BYTEBUF, PF_NA}, 
            {"tty", PT_INT32, PF_DEC},
            {"pgid", PT_PID, PF_DEC}, 
            {"loginuid", PT_INT32, PF_DEC} 
        } 
    }
    ......    
}
将参数装填进buffer的过程在
		if (likely(g_ppm_events[event_type].filler_callback)) {
		    cbres = g_ppm_events[event_type].filler_callback(&args);
		} else {
			pr_err("corrupted filler for event type %d: NULL callback\n", event_type);
			ASSERT(0);
		}
2.关于PPME_SYSCALL_EXECVE_19_E 和 PPME_SYSCALL_EXECVE_19_X的回调函数
在filters_table.c中有
	[PPME_SYSCALL_EXECVE_19_E] = {FILLER_REF(sys_execve_e)},
	[PPME_SYSCALL_EXECVE_19_X] = {FILLER_REF(proc_startupdate)},
    
FILTER_REF(proc_startupdate)对应的是ppm_filters.c里面的
int f_proc_startupdate(struct event_filter_arguments *args) 函数
这个函数非常有意思，
int f_proc_startupdate(struct event_filler_arguments *args)
{
	unsigned long val;
	int res = 0;
	unsigned int exe_len = 0;  /* the length of the executable string */
	int args_len = 0; /*the combined length of the arguments string + executable string */
	struct mm_struct *mm = current->mm;
	int64_t retval;
	int ptid;
	char *spwd = "";
	long total_vm = 0;
	long total_rss = 0;
	long swap = 0;
	int available = STR_STORAGE_SIZE;
    ......
    res = val_to_ring(args, (uint64_t)(long)spwd, 0, false, 0);
}
