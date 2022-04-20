/*
 * Tencent is pleased to support the open source community by making BK-CI 蓝鲸持续集成平台 available.
 *
 * Copyright (C) 2019 THL A29 Limited, a Tencent company.  All rights reserved.
 *
 * BK-CI 蓝鲸持续集成平台 is licensed under the MIT license.
 *
 * A copy of the MIT License is included in this file.
 *
 *
 * Terms of the MIT License:
 * ---------------------------------------------------
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
 * documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all copies or substantial portions of
 * the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
 * LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
 * NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package com.tencent.devops.auth.service.ci.impl

import com.google.common.cache.CacheBuilder
import com.tencent.bk.sdk.iam.constants.ManagerScopesEnum
import com.tencent.devops.auth.constant.AuthMessageCode
import com.tencent.devops.auth.entity.GroupMemberInfo
import com.tencent.devops.auth.pojo.dto.GroupMemberDTO
import com.tencent.devops.auth.pojo.dto.RoleMemberDTO
import com.tencent.devops.auth.pojo.dto.UserGroupInfoDTO
import com.tencent.devops.auth.pojo.enum.UserType
import com.tencent.devops.auth.pojo.vo.ProjectMembersVO
import com.tencent.devops.auth.service.AuthGroupMemberService
import com.tencent.devops.auth.service.AuthGroupService
import com.tencent.devops.auth.service.ci.PermissionRoleMemberService
import com.tencent.devops.auth.service.iam.IamCacheService
import com.tencent.devops.auth.service.iam.PermissionGradeService
import com.tencent.devops.common.api.exception.ErrorCodeException
import com.tencent.devops.common.service.utils.MessageCodeUtil
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import java.util.concurrent.TimeUnit

abstract class AbsPermissionRoleMemberImpl @Autowired constructor(
    private val permissionGradeService: PermissionGradeService,
    private val groupService: AuthGroupService,
    private val iamCacheService: IamCacheService,
    private val groupMemberService: AuthGroupMemberService
) : PermissionRoleMemberService {

    private val projectMemberCache = CacheBuilder.newBuilder()
        .maximumSize(20)
        .expireAfterWrite(5, TimeUnit.MINUTES)
        .build<String, ProjectMembersVO>()

    override fun createRoleMember(
        userId: String,
        projectId: String,
        roleId: Int,
        members: List<RoleMemberDTO>,
        managerGroup: Boolean,
        checkAGradeManager: Boolean?,
        expiredDay: Long
    ) {
        // 管理员才能做加入操作
        if (checkAGradeManager == true) {
            permissionGradeService.checkGradeManagerUser(userId, projectId)
        }

        // 过期天数最大不能超过一年
        if (expiredDay > 365) {
            logger.warn("$userId $projectId $roleId expiredDay more 365 days")
            throw ErrorCodeException(
                errorCode = AuthMessageCode.EXPIRED_DAY_ERROR,
                defaultMessage = MessageCodeUtil.getCodeLanMessage(AuthMessageCode.EXPIRED_DAY_ERROR)
            )
        }

        // 每次最多添加100个人
        if (members.size > 100) {
            logger.warn("$userId $projectId $roleId create member more 100")
            throw ErrorCodeException(
                errorCode = AuthMessageCode.ADD_GROUP_USER_MORE_MUST,
                defaultMessage = MessageCodeUtil.getCodeLanMessage(AuthMessageCode.ADD_GROUP_USER_MORE_MUST)
            )
        }

        // 单个用户组最多有500个用户或组织
        if (groupMemberService.groupCount(projectId, roleId) > 500) {
            logger.warn("$userId $projectId $roleId group user more 500")
            throw ErrorCodeException(
                errorCode = AuthMessageCode.GROUP_USER_COUNT_OUT_OF_BOUNDS,
                defaultMessage = MessageCodeUtil.getCodeLanMessage(AuthMessageCode.GROUP_USER_COUNT_OUT_OF_BOUNDS)
            )
        }

        // 获取用户组类型, 确保用户组存在
        val groupInfo = groupService.getGroupCode(roleId)
            ?: throw ErrorCodeException(
                errorCode = AuthMessageCode.GROUP_NOT_EXIST,
                defaultMessage = MessageCodeUtil.getCodeLanMessage(AuthMessageCode.GROUP_NOT_EXIST)
            )
        val userIds = mutableListOf<String>()
        members.map { userIds.add(it.id) }

        // 判断用户是否已加入用户组
        if (groupMemberService.usersJoinGroup(userIds, roleId)) {
            throw ErrorCodeException(
                errorCode = AuthMessageCode.USER_EXIST_JOIN_GROUP,
                defaultMessage = MessageCodeUtil.getCodeLanMessage(
                    AuthMessageCode.USER_EXIST_JOIN_GROUP
                )
            )
        }

        val createMembers = mutableListOf<GroupMemberInfo>()
        members.forEach {
            createMembers.add(
                GroupMemberInfo(
                    userId = it.id,
                    userType = it.type == UserType.USER,
                    projectCode = projectId,
                    groupId = roleId,
                    expiredDay = expiredDay,
                    groupType = groupInfo.groupType
                )
            )
        }
        groupMemberService.batchCreateGroupMember(createMembers)
    }

    override fun deleteRoleMember(
        executeUserId: String,
        projectId: String,
        roleId: Int,
        deleteUserId: String,
        type: ManagerScopesEnum,
        managerGroup: Boolean
    ) {
        // 如果不是本人操作,需校验操作人是否为项目管理员。如果是本人操作是为主动退出用户组
        if (executeUserId != deleteUserId) {
            permissionGradeService.checkGradeManagerUser(executeUserId, projectId)
        }
        groupMemberService.deleteGroupMember(roleId, deleteUserId)
    }

    override fun getRoleMember(
        projectId: String,
        roleId: Int,
        page: Int?,
        pageSiz: Int?
    ): GroupMemberDTO? {
        return groupMemberService.getRoleMember(roleId, projectId)
    }

    override fun getProjectAllMember(projectId: String, page: Int?, pageSiz: Int?): ProjectMembersVO? {
        return groupMemberService.getProjectMemberList(projectId)
    }

    override fun getUserGroups(projectId: String, userId: String): List<UserGroupInfoDTO>? {
        return groupMemberService.getUserGroupByProject(projectId, userId)
    }

    override fun renewalUser(
        projectId: String,
        roleId: Int,
        executeUser: String,
        renewalUser: String,
        expiredDay: Long,
    ): Boolean {
        // 校验用户是否有加入用户组
        if (!groupMemberService.userJoinGroup(renewalUser, roleId)) {
            throw ErrorCodeException(
                errorCode = AuthMessageCode.USER_EXIST_JOIN_GROUP,
                defaultMessage = MessageCodeUtil.getCodeLanMessage(AuthMessageCode.USER_EXIST_JOIN_GROUP)
            )
        }

        // 续约天数最多为1年
        val expiredTime = if (expiredDay > MAX_EXPIRED_DAY) {
            MAX_EXPIRED_DAY
        } else expiredDay

        return groupMemberService.renewalUser(
            userId = renewalUser,
            expiredDay = expiredTime as Long,
            groupId = roleId
        ) == 1
    }

    abstract fun checkUser(userId: String)

    companion object {
        const val MAX_EXPIRED_DAY = 365
        val logger = LoggerFactory.getLogger(AbsPermissionRoleMemberImpl::class.java)
    }
}