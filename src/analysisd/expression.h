/* Copyright (C) 2015-2020, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef EXPRESSION_H_
#define EXPRESSION_H_

#include "shared.h"


/**
 * @brief
 */
typedef enum { 
    EXP_TYPE_OSREGEX,
    EXP_TYPE_OSMATCH,
    EXP_TYPE_STRING,
    EXP_TYPE_OSIP_ARRAY,
    EXP_TYPE_PCRE2
} w_exp_type_t;


/**
 * @brief
 */
typedef struct {
    w_exp_type_t exp_type;

    union {
        OSRegex * regex;
        OSMatch * match;
        char * string;
        os_ip ** ips;
    };

    bool negate;
} w_expression_t;


/**
 * @brief
 * @param
 */
void w_calloc_expression_t(w_expression_t ** var, w_exp_type_t type);

/**
 * @brief add ip to array
 * @param ips array which save ip
 * @param ip ip to save
 * @return true on success, otherwise false
 */
bool w_expression_add_osip(w_expression_t ** var, char * ip);

#endif
