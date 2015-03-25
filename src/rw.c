#include "rw.h"

int write_apinfo(char *fname, char *tagname, char *value)
{
	FILE *fp;
	int len;
	char *str = NULL, buf[1024] = {0}, name[128] = {0}
	,*nstr = NULL, *tmp = NULL, *ntmp = NULL;

	if (!(fname && tagname && value))
		return -1;
	sprintf(name, "/etc/%s", fname);
	if (access(name, F_OK) != 0)
		return -1;
	if ((fp = fopen(name, "r")) == NULL)
		return -1;
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	if (len != 0)
	{
		if ((str = alloca(len)) == NULL)
		{
			fclose(fp);
			return -1;
		}
		memset(str, 0, len);
		fseek(fp, 0, SEEK_SET);
		fread(str, len, sizeof(char), fp);
		str[len] = 0;
	}
	fclose(fp);

	sprintf(buf, "%s=%s\n", tagname, value);
	len += strlen(buf);
	if ((nstr = alloca(len)) == NULL)
		return -1;
	memset(nstr, 0, len);
	if (str == NULL || (tmp = strstr(str, tagname)) == NULL)
	{
		if (str == NULL)
			strcpy(nstr, buf);
		else
			sprintf(nstr, "%s%s", str, buf);
	}
	else
	{
		strncpy(nstr, str, tmp - str);
		strcat(nstr, buf);
		if ((ntmp = strstr(tmp + strlen(tagname), "\n")) == NULL)
			return -1;
		strcat(nstr, ntmp + 1);
	}
	if ((fp = fopen(name, "w+")) == NULL)
		return -1;
	fwrite(nstr, strlen(nstr), sizeof(char), fp);
	fclose(fp);
	return 0;
}

char *read_apinfo(char *fname, char *tagname, char *value)
{
	FILE *fp;
	char buf[1024] = {0}, name[128] = {0}, *str = NULL;
	if (!(fname && tagname && value))
		return NULL;

	sprintf(name, "/etc/%s", fname);
	if (access(name, F_OK) != 0)
		return NULL;
	if ((fp = fopen(name, "r")) == NULL)
		return NULL;

	while(!feof(fp))
	{
		bzero(buf, sizeof(buf));
		if (fgets(buf, sizeof(buf), fp) == NULL)
			continue;
		if ((str = strstr(buf, tagname)) == NULL)
			continue;
		fclose(fp);
		strcpy(value, str + strlen(tagname) + 1);
		value[strlen(value) - 1] = 0;
		return value;
	}
	fclose(fp);
	return NULL;
}
void del_apinfo(char *fname, char *tagname)
{
	FILE *fp;
	int len;
	char *str = NULL, buf[1024] = {0}, name[128] = {0}
	,*nstr = NULL, *tmp = NULL, *ntmp = NULL;

	if (!(fname && tagname))
		return;

	sprintf(name, "/etc/%s", fname);
	if (access(name, F_OK) != 0)
		return;

	if ((fp = fopen(name, "r")) == NULL)
		return;
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	if (len == 0)
	{
		fclose(fp);
		return;
	}
	if ((str = alloca(len)) == NULL)
		return;
	memset(str, 0, len);
	fseek(fp, 0, SEEK_SET);
	fread(str, len, sizeof(char), fp);
	str[len] = 0;
	fclose(fp);

	if ((tmp = strstr(str, tagname)) == NULL)
		return;
	if ((nstr = alloca(len)) == NULL)
		return;
	memset(nstr, 0, len);

	strncpy(nstr, str, tmp - str);
	strcat(nstr, buf);
	if ((ntmp = strstr(tmp + strlen(tagname), "\n")) == NULL)
		return;
	strcat(nstr, ntmp + 1);

	if ((fp = fopen(name, "w+")) == NULL)
		return;
	fwrite(nstr, strlen(nstr), sizeof(char), fp);
	fclose(fp);
	return;
}



