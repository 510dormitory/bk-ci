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

package com.tencent.devops.project.service.impl

import com.tencent.devops.auth.api.service.ServicePermissionAuthResource
import com.tencent.devops.auth.api.service.ServiceProjectAuthResource
import com.tencent.devops.auth.api.service.ServiceRoleMemberResource
import com.tencent.devops.auth.api.service.ServiceRoleResource
import com.tencent.devops.auth.pojo.dto.RoleMemberDTO
import com.tencent.devops.auth.pojo.enum.UserType
import com.tencent.devops.common.auth.api.AuthPermission
import com.tencent.devops.common.auth.api.pojo.ResourceRegisterInfo
import com.tencent.devops.common.client.Client
import com.tencent.devops.project.pojo.user.UserDeptDetail
import com.tencent.devops.project.service.ProjectPermissionService
import org.springframework.beans.factory.annotation.Autowired

class SimpleProjectPermissionServiceImpl @Autowired constructor(
    private val client: Client
) : ProjectPermissionService {

    override fun verifyUserProjectPermission(accessToken: String?, projectCode: String, userId: String): Boolean {
        return client.get(ServiceProjectAuthResource::class).isProjectUser(
            token = accessToken ?: "",
            userId = userId,
            projectCode = projectCode
        ).data!!
    }

    override fun getUserProjectsAvailable(userId: String): Map<String, String> {
        val projectMap = mutableMapOf<String, String>()
        val userProjects = client.get(ServiceProjectAuthResource::class).getUserProjects("", userId).data
        userProjects?.forEach {
            projectMap[it] = it
        }
        return projectMap
    }

    override fun getUserProjects(userId: String): List<String> {
        return client.get(ServiceProjectAuthResource::class).getUserProjects(
            token = "",
            userId = userId
        ).data ?: emptyList()
    }

    override fun modifyResource(projectCode: String, projectName: String) {
        return
    }

    override fun deleteResource(projectCode: String) {
        return
    }

    /**
     * 创建项目权限步骤：
     * 1. 创建项目下的管理员用户组
     * 2. 把创建人添加到管理员组
     */
    override fun createResources(
        userId: String,
        accessToken: String?,
        resourceRegisterInfo: ResourceRegisterInfo,
        userDeptDetail: UserDeptDetail?
    ): String {
        val roleId = client.get(ServiceRoleResource::class).createProjectManager(
            userId = userId,
            projectCode = resourceRegisterInfo.resourceCode
        ).data
        val member = RoleMemberDTO(
            type = UserType.USER,
            id = userId
        )
        client.get(ServiceRoleMemberResource::class).createRoleMember(
            userId = userId,
            roleId = roleId!!.toInt(),
            projectId = resourceRegisterInfo.resourceCode,
            managerGroup = true,
            members = arrayOf(member).toList(),
            expiredDay = 365
        )
        return roleId.toString()
    }

    override fun verifyUserProjectPermission(
        accessToken: String?,
        projectCode: String,
        userId: String,
        permission: AuthPermission
    ): Boolean {
        return client.get(ServicePermissionAuthResource::class).validateUserResourcePermission(
            userId = userId,
            token = "",
            projectCode = projectCode,
            resourceCode = projectCode,
            action = permission.value,
        ).data!!
    }
}
