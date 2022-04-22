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

import com.tencent.devops.auth.constant.AuthMessageCode
import com.tencent.devops.auth.pojo.dto.GroupDTO
import com.tencent.devops.auth.pojo.dto.ProjectRoleDTO
import com.tencent.devops.auth.service.AuthCustomizePermissionService
import com.tencent.devops.auth.service.AuthGroupService
import com.tencent.devops.auth.service.action.ActionService
import com.tencent.devops.auth.service.action.BkResourceService
import com.tencent.devops.auth.service.ci.PermissionRoleService
import com.tencent.devops.auth.service.iam.PermissionGradeService
import com.tencent.devops.common.api.exception.ErrorCodeException
import com.tencent.devops.common.auth.api.pojo.DefaultGroupType
import com.tencent.devops.common.service.utils.MessageCodeUtil
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired

abstract class AbsPermissionRoleServiceImpl @Autowired constructor(
    private val groupService: AuthGroupService,
    private val resourceService: BkResourceService,
    private val actionsService: ActionService,
    private val authCustomizePermissionService: AuthCustomizePermissionService,
    private val permissionGradeService: PermissionGradeService
) : PermissionRoleService {
    override fun createPermissionRole(
        userId: String,
        projectId: String,
        projectCode: String,
        groupInfo: ProjectRoleDTO
    ): Int {
        var groupType: Boolean?
        var groupName: String
        var displayName: String
        if (!DefaultGroupType.contains(groupInfo.code)) {
            groupType = false
            groupName = groupInfo.name
            displayName = groupInfo.displayName ?: groupInfo.name
        } else {
            groupType = true
            groupName = groupInfo.name
            displayName = DefaultGroupType.get(groupInfo.code).displayName
        }

        checkRoleCode(groupInfo.code, groupInfo.defaultGroup ?: true)
        checkRoleName(groupInfo.name, groupInfo.defaultGroup ?: true)
        managerCheck(userId, projectId)

        val roleId = groupService.createGroup(
            userId = userId,
            projectCode = projectCode,
            groupInfo = GroupDTO(
                groupCode = groupInfo.code,
                groupType = groupType,
                groupName = groupName,
                displayName = displayName,
                relationId = null,
                desc = groupInfo.description
            )
        )
        return roleId
    }

    override fun createProjectManager(userId: String, projectId: String): Int {
        if (groupService.getGroupByCode(projectId, DefaultGroupType.MANAGER.value) != null) {
            logger.warn("$projectId ${DefaultGroupType.MANAGER.value} is exist")
            throw ErrorCodeException(
                errorCode = AuthMessageCode.GROUP_EXIST,
                defaultMessage = MessageCodeUtil.getCodeLanMessage(AuthMessageCode.GROUP_EXIST)
            )
        }
        return groupService.createGroup(
            userId = userId,
            projectCode = projectId,
            groupInfo = GroupDTO(
                groupCode = DefaultGroupType.MANAGER.value,
                groupType = true,
                groupName = DefaultGroupType.MANAGER.displayName,
                displayName = DefaultGroupType.MANAGER.displayName,
                relationId = null,
                desc = ""
            )
        )
    }

    override fun updatePermissionRole(
        userId: String,
        projectId: String,
        roleId: Int,
        groupInfo: ProjectRoleDTO
    ) {
        // 校验用户组名称
        checkRoleName(groupInfo.name, true)
        managerCheck(userId, projectId)
        groupService.updateGroup(userId, roleId, groupInfo)
    }

    override fun updateGroupDesc(
        userId: String,
        projectId: String,
        roleId: Int,
        desc: String,
    ): Boolean {
        managerCheck(userId, projectId)
        return groupService.updateGroupDesc(
            userId = userId,
            projectCode = projectId,
            groupId = roleId,
            desc = desc
        ) == 1
    }

    override fun deletePermissionRole(userId: String, projectId: String, roleId: Int) {
        managerCheck(userId, projectId)
        groupService.deleteGroup(roleId)
    }

    override fun rolePermissionStrategy(
        userId: String,
        projectCode: String,
        roleId: Int,
        permissionStrategy: Map<String, List<String>>
    ): Boolean {
        val groupInfo = groupService.getGroupById(roleId) ?: throw ErrorCodeException(
            errorCode = AuthMessageCode.GROUP_NOT_EXIST,
            defaultMessage = MessageCodeUtil.getCodeLanMessage(AuthMessageCode.GROUP_NOT_EXIST)
        )
        // 默认用户组不能调整权限策略
        if (groupInfo.groupType) {
            throw ErrorCodeException(
                errorCode = AuthMessageCode.DEFAULT_GROUP_NOT_ALLOW_UPDATE,
                defaultMessage = MessageCodeUtil.getCodeLanMessage(AuthMessageCode.DEFAULT_GROUP_NOT_ALLOW_UPDATE)
            )
        }
        managerCheck(userId, projectCode)

        permissionStrategy.forEach { resource, actions ->
            // 校验资源和action是否存在
            if (resourceService.getResource(resource) == null) {
                logger.info("createCustomizePermission $userId$roleId$resource not exist")
                throw ErrorCodeException(
                    errorCode = AuthMessageCode.RESOURCE_NOT_EXSIT,
                    defaultMessage = MessageCodeUtil.getCodeMessage(
                        messageCode = AuthMessageCode.RESOURCE_NOT_EXSIT, params = arrayOf(resource))
                )
            }

            if (!actionsService.checkSystemAction(actions)) {
                AuthCustomizePermissionService.logger.info("createCustomizePermission $userId$roleId$actions not exist")
                throw ErrorCodeException(
                    errorCode = AuthMessageCode.PERMISSION_MODEL_CHECK_FAIL,
                    defaultMessage = MessageCodeUtil.getCodeLanMessage(AuthMessageCode.PERMISSION_MODEL_CHECK_FAIL)
                )
            }
        }
        permissionStrategy.forEach { resource, actions ->
            val action = actions.joinToString(",")
            logger.info("$projectCode $roleId $resource $actions $action set permission")
            authCustomizePermissionService.createCustomizePermission(
                userId = userId,
                groupId = roleId,
                resourceType = resource,
                actions = action
            )
        }
        return rolePermissionStrategyExt(userId, projectCode, roleId, permissionStrategy)
    }

    abstract fun rolePermissionStrategyExt(
        userId: String,
        projectCode: String,
        roleId: Int,
        permissionStrategy: Map<String, List<String>>
    ): Boolean


    private fun checkRoleCode(code: String, defaultGroup: Boolean) {
        // 校验用户组名称
        if (defaultGroup) {
            // 若为默认分组,需校验提供用户组是否在默认分组内。
            if (!DefaultGroupType.contains(code)) {
                logger.warn("create default group but name is error code $code")
                // 不在默认分组内则直接报错
                throw ErrorCodeException(
                    errorCode = AuthMessageCode.DEFAULT_GROUP_ERROR,
                    defaultMessage = MessageCodeUtil.getCodeLanMessage(AuthMessageCode.DEFAULT_GROUP_ERROR)
                )
            }
        } else {
            // 非默认分组,不能使用默认分组组名
            if (DefaultGroupType.contains(code)) {
                logger.warn("create customize group code is equal default group code $code")
                throw ErrorCodeException(
                    errorCode = AuthMessageCode.UN_DEFAULT_GROUP_ERROR,
                    defaultMessage = MessageCodeUtil.getCodeLanMessage(AuthMessageCode.UN_DEFAULT_GROUP_ERROR)
                )
            }
        }
    }

    private fun checkRoleName(name: String, defaultGroup: Boolean) {
        // 校验用户组名称
        if (defaultGroup) {
            // 若为默认分组,需校验提供用户组是否在默认分组内。
            if (!DefaultGroupType.containsDisplayName(name)) {
                logger.warn("create default group but name is error name $name")
                // 不在默认分组内则直接报错
                throw ErrorCodeException(
                    errorCode = AuthMessageCode.DEFAULT_GROUP_ERROR,
                    defaultMessage = MessageCodeUtil.getCodeLanMessage(AuthMessageCode.DEFAULT_GROUP_ERROR)
                )
            }
        } else {
            // 非默认分组,不能使用默认分组组名
            if (DefaultGroupType.containsDisplayName(name)) {
                logger.warn("create customize group name is equal default group name $name")
                throw ErrorCodeException(
                    errorCode = AuthMessageCode.UN_DEFAULT_GROUP_ERROR,
                    defaultMessage = MessageCodeUtil.getCodeLanMessage(AuthMessageCode.UN_DEFAULT_GROUP_ERROR)
                )
            }
        }
    }

    // 校验操作人是否有项目分级管理员权限
    private fun managerCheck(userId: String, projectId: String) {
        permissionGradeService.checkGradeManagerUser(userId, projectId)
    }

    companion object {
        private val logger = LoggerFactory.getLogger(AbsPermissionRoleServiceImpl::class.java)
    }
}
