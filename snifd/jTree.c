/***************************************************************************
 *          ___       ___
 *         /   \     /   \    VESvault
 *         \__ /     \ __/    Encrypt Everything without fear of losing the Key
 *            \\     //                   https://vesvault.com https://ves.host
 *             \\   //
 *     ___      \\_//
 *    /   \     /   \         libVES:                      VESvault API library
 *    \__ /     \ __/
 *       \\     //            VES Utility:   A command line interface to libVES
 *        \\   //
 *         \\_//              - Key Management and Exchange
 *         /   \              - Item Encryption and Sharing
 *         \___/              - Stream Encryption
 *
 *
 * (c) 2018 VESvault Corp
 * Jim Zubov <jz@vesvault.com>
 *
 * GNU General Public License v3
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * jTree.c                    jTree: A binary tree
 *
 ***************************************************************************/
#include <stddef.h>
#include <stdlib.h>
#include "jTree.h"

jTree *jTree_init(jTree *jtree) {
    if (!jtree) jtree = malloc(sizeof(jTree));
    jtree->left = jtree->right = jtree->back = NULL;
    jtree->data = NULL;
    jtree->ldepth = jtree->rdepth = 0;
    return jtree;
}

#define JTREE_BAL_LVL	2

#define	jTree_BAL1(jtree, r, a, b, ad, bd)	if ((r = jtree->a) && (r->data || (r = NULL))) {\
    r->back = jtree->back;\
    if ((jtree->a = r->b)) jtree->a->back = jtree;\
    jtree->ad = r->bd;\
    r->b = jtree;\
    jtree->back = r;\
    r->bd = (jtree->ad > jtree->bd ? jtree->ad : jtree->bd) + 1;\
}

#define	jTree_BAL2(jtree, r, a, b, ad, bd)	if ((r = jtree->a->b) && (r->data || (r = NULL))) {\
    r->back = jtree->back;\
    if ((jtree->a->b = r->a)) jtree->a->b->back = jtree->a;\
    jtree->a->bd = r->ad;\
    r->ad = (jtree->a->ad > r->ad ? jtree->a->ad : r->ad) + 1;\
    r->a = jtree->a;\
    r->a->back = r;\
    if ((jtree->a = r->b)) jtree->a->back = jtree;\
    jtree->ad = r->bd;\
    r->b = jtree;\
    r->b->back = r;\
    r->bd = (jtree->ad > jtree->bd ? jtree->ad : jtree->bd) + 1;\
}

void **jTree_seek(jTree **ptree, void *term, void *arg, int (* cmpfn)(void *data, void *term, void *arg), unsigned char *depth) {
    jTree *jtree = *ptree;
    if (!jtree) {
	if (!depth) return NULL;
	jtree = *ptree = jTree_init(NULL);
	*depth = 1;
	return &jtree->data;
    }
    void **rs;
    int c = jtree->data ? cmpfn(jtree->data, term, arg) : 0;
    if (!c) {
	rs = &jtree->data;
    } else if (c < 0) {
	rs = jTree_seek(&jtree->right, term, arg, cmpfn, depth);
	if (depth) {
	    jtree->right->back = jtree;
	    jtree->rdepth = *depth;
	    if (jtree->rdepth > jtree->ldepth + JTREE_BAL_LVL) {
		jTree *r;
		if (jtree->right->ldepth > jtree->ldepth) {
		    jTree_BAL2(jtree, r, right, left, rdepth, ldepth)
		} else {
		    jTree_BAL1(jtree, r, right, left, rdepth, ldepth)
		}
		if (r) jtree = *ptree = r;
	    }
	}
    } else {
	rs = jTree_seek(&jtree->left, term, arg, cmpfn, depth);
	if (depth) {
	    jtree->left->back = jtree;
	    jtree->ldepth = *depth;
	    if (jtree->ldepth > jtree->rdepth + JTREE_BAL_LVL) {
		jTree *r;
		if (jtree->left->rdepth > jtree->rdepth) {
		    jTree_BAL2(jtree, r, left, right, ldepth, rdepth)
		} else {
		    jTree_BAL1(jtree, r, left, right, ldepth, rdepth)
		}
		if (r) jtree = *ptree = r;
	    }
	}
    }
    if (depth) *depth = (jtree->ldepth > jtree->rdepth ? jtree->ldepth : jtree->rdepth) + 1;
    return rs;
}

void **jTree_first(jTree *jtree) {
    if (!jtree) return NULL;
    while (jtree->left) jtree = jtree->left;
    return &jtree->data;
}

void **jTree_last(jTree *jtree) {
    if (!jtree) return NULL;
    while (jtree->right) jtree = jtree->right;
    return &jtree->data;
}

void **jTree_next(void **pdata) {
    if (!pdata) return NULL;
    jTree *jtree = (jTree *)(((char *) pdata) - offsetof(jTree, data));
    if (jtree->right) return jTree_first(jtree->right);
    jTree *bk;
    for (bk = jtree->back; bk; jtree = bk, bk = bk->back) {
	if (bk->left == jtree) return &bk->data;
    }
    return NULL;
}

void **jTree_prev(void **pdata) {
    if (!pdata) return NULL;
    jTree *jtree = (jTree *)(((char *) pdata) - offsetof(jTree, data));
    if (jtree->left) return jTree_last(jtree->left);
    jTree *bk;
    for (bk = jtree->back; bk; jtree = bk, bk = bk->back) {
	if (bk->right == jtree) return &bk->data;
    }
    return NULL;
}

void jTree_delete(jTree **ptree, void **pdata) {
    if (!pdata) return;
    jTree *jtree = (jTree *)(((char *) pdata) - offsetof(jTree, data));
    jTree *jl, *jr, *jnew;
    jTree *jback = jtree->back;
    jtree->data = NULL;
    jtree->ldepth = jtree->rdepth = 0;
    jl = jtree->left;
    jr = jtree->right;
    if (jl && !jl->data) jl = NULL;
    if (jr && !jr->data) jr = NULL;
    if (jl) while (jl->right && jl->right->data) jl = jl->right;
    if (jr) while (jr->left && jr->left->data) jr = jr->left;
    jTree *jlnull = jl ? jl->right : jtree->left;
    jTree *jrnull = jr ? jr->left : jtree->right;
    jTree **pt;
    if (jl) {
	jnew = jl;
	if (jl->left) jl->left->back = jl->back;
	if (jl->back->right == jl) {
	    jl->back->right = jl->left;
	    jl->back->rdepth = jl->ldepth;
	} else {
	    jl->back->left = jl->left;
	    jl->back->ldepth = jl->ldepth;
	}
	if (jr) {
	    pt = &jr->left;
	    jr->left = jtree;
	    jtree->back = jr;
	} else {
	    pt = &jnew->right;
	    jtree->right = jtree;
	}
    } else if (jr) {
	jnew = jr;
	if (jr->right) jr->right->back = jr->back;
	if (jr->back->left == jr) {
	    jr->back->left = jr->right;
	    jr->back->ldepth = jr->rdepth;
	} else {
	    jr->back->right = jr->right;
	    jr->back->rdepth = jr->rdepth;
	}
	if (jl) {
	    pt = &jl->right;
	    jl->right = jtree;
	    jtree->back = jl;
	} else {
	    pt = &jnew->left;
	    jtree->left = jtree;
	}
    } else return;
    jTree *jd = jnew->back;
    if ((jnew->left = jtree->left)) jnew->left->back = jnew;
    if ((jnew->right = jtree->right)) jnew->right->back = jnew;
    jnew->ldepth = jtree->ldepth;
    jnew->rdepth = jtree->rdepth;
    jnew->back = jback;
    if (jback) {
	if (jback->left == jtree) jback->left = jnew;
	if (jback->right == jtree) jback->right = jnew;
    } else {
	*ptree = jnew;
    }
    if ((jtree->left = jlnull)) jlnull->back = jtree;
    if ((jtree->right = jrnull)) jrnull->back = jtree;
    jTree *jdn;
    for (; (jdn = jd->back); jd = jdn) {
	int d = jd->data ? ((jd->ldepth > jd->rdepth ? jd->ldepth : jd->rdepth) + 1) : 0;
	if (jdn->left == jd) jdn->ldepth = d;
	else jdn->rdepth = d;
    }
    jTree_collapse(pt);
}

unsigned char jTree_collapse(jTree **ptree) {
    jTree *jtree = *ptree;
    if (!jtree) return 0;
    jtree->ldepth = jTree_collapse(&jtree->left);
    jtree->rdepth = jTree_collapse(&jtree->right);
    if (!jtree->data && !jtree->left && !jtree->right) {
	free(jtree);
	*ptree = NULL;
	return 0;
    }
    return (jtree->ldepth > jtree->rdepth ? jtree->ldepth : jtree->ldepth) + 1;
}
