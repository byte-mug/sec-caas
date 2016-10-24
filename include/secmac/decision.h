/*
 * Copyright (c) 2016 Simon Schmidt
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#pragma once

/*
 * Dislaimer: DAC,ACL,RBAC,TE and MLS refer to theoretical concepts, the actual
 *            implementations may differ as they may be more sophisticated.
 *
 * The basic idea of the decision-architecture is, that we have one or more
 * "security decision modules" (akin Linux LSM or BSD MAC-Framework). The scope
 * of these modules range from simple DAC to highly sophisticated multilevel
 * security and type enforcement. Therefore we will have a combination of
 * multiple modules like DAC,ACL,RBAC,TE and MLS.
 *
 * Generally, we assume, that some policies (like DAC,ACL and RBAC) grant
 * permissions to parties (Users,Subjects, etc.) while other policies (like MLS)
 * revoke permissions from parties, even if other policies would grant them.
 * In order to support such a complex decision, we need to define a more
 * sophisticated decision-model than the boolean model (yes/no), hence the fact
 * of having multiple decision modules leads to conflicting decisions.
 * For example, DAC grants permissions to the Owner, ACL grant permissions to
 * others and the permissions of both DAC and ACL accumulate - thus the decision
 * to grant permissions overrides the dicision not to grant permissions. On the
 * Other hand, MLS usually may not grant additional permissions but revokes
 * permissions them from parties, that have been granted by other modules.
 * Moreso, a more sophisticated ACL system may even decide wether or not to
 * grant permissions or to revoke them - thus overriding the decision of the
 * DAC module in both directions or not and acting as restrictive as an MLS
 * module.
 *
 * To archieve this flexibility, instead of a boolean, we define three different
 * decisions:  ALLOW (allow), NONE (don't allow) and DENY (explicitly deny).
 */

typedef enum secmac_decision {
	/* no permission */
	secmac_NONE  = 0,
	/* grant permission; overrides NONE */
	secmac_ALLOW = 1,
	/* deny permission; overrides ALLOW */
	secmac_DENY  = 2,
} secmac_d ;

static inline secmac_d secmac_reduce(secmac_d a,secmac_d b){
	return a>b?a:b;
}
static inline int secmac_allowed(secmac_d a){
	return a == secmac_ALLOW;
}

