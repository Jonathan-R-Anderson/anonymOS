#ifndef __COMPLIANCE_H
#define __COMPLIANCE_H
#include "argus.h"

typedef enum {
    COMPLIANCE_CIS_LINUX = 0,
    COMPLIANCE_PCI_DSS,
    COMPLIANCE_NIST_CSF,
    COMPLIANCE_SOC2,
} compliance_framework_t;

void compliance_init(compliance_framework_t framework, const char *report_path);
void compliance_record_event(const event_t *ev);
void compliance_record_alert(const event_t *ev, const char *rule_name, const char *severity);
int  compliance_write_report(void);   /* writes HTML; returns 0 on success */
void compliance_destroy(void);
#endif
