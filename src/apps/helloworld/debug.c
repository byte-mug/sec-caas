#include <stdio.h>
#include <secmac/fw_res.h>


static void print_secmac_res_module_t (const secmac_res_module_t* module){
	unsigned i;
	printf("    secmac_res_module_t{\n");
	printf("      subject_attrs=");
	for(i=0;i<(module->subject_attrs_len);++i)
		printf("%d, ",(int)(module->subject_attrs_list[i]));
	printf("\n");
	printf("      resource_attrs=");
	for(i=0;i<(module->resource_attrs_len);++i)
		printf("%d, ",(int)(module->resource_attrs_list[i]));
	printf("\n");
	printf("    },\n");
}

void print_secmac_res_fw_t(const secmac_res_fw_t* fw){
	unsigned i;
	printf("secmac_res_fw_t{\n");
	/*---------------------------------------------------------------------*/
	printf("  subject_attrs=");
	for(i=0;i<(fw->subject_attrs_len);++i)
		printf("%s, ",(fw->subject_attrs_list[i]));
	printf("\n");
	printf("  resource_attrs=");
	for(i=0;i<(fw->resource_attrs_len);++i)
		printf("%s, ",(fw->resource_attrs_list[i]));
	printf("\n");
	/*---------------------------------------------------------------------*/
	printf("  modules={\n");
	for(i=0;i<(fw->modules_len);++i)
		print_secmac_res_module_t(fw->modules_list[i]);
	printf("  }\n");
	printf("}\n");
}