#include <secmac/decision.h>
#include <secmac/resource.h>
#include <secmac/fw_res.h>
#include <testfw/test_res.h>
#include <stdio.h>
#include <secacl/aclfmt.h>

static const char* const subatt[] = {
	SECMAC_POSIX_CRED,
	(const char*)(0)
};
static const char* const resatt[] = {
	SECMAC_POSIX_STAT,
	(const char*)(0)
};

static secmac_d my_op (
		const secmac_data_t* sub_attr,
		const secmac_data_t* res_attr,
		uint16_t secmac_op)
{
	return secmac_NONE;
}

static const secmac_res_hook_t hook = {
	.subject_attrs = subatt,
	.resource_attrs = resatt,
	.OP_hook = my_op
};

void print_secmac_res_fw_t(const secmac_res_fw_t* fw);

secmac_data_entry_t entries[] = {
};

int main(){
	secmac_data_t *subbuf, *resbuf;
	secmac_res_fw_t* sec = secmac_res_new();
	secmac_res_add_hook(sec,&hook);
	print_secmac_res_fw_t(sec);
	
	subbuf = testfw_getdata(entries,0,sec->subject_attrs_list,sec->subject_attrs_len);
	resbuf = testfw_getdata(entries,0,sec->resource_attrs_list,sec->resource_attrs_len);
	
	secmac_d result = secmac_res_check_op(sec,subbuf,resbuf,0);
	printf("%s\n",secmac_allowed(result)?"Yes":"No");
	return 0;
}


