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
 *
 */

package com.tencent.devops.auth.api.user

import com.tencent.devops.auth.pojo.DefaultGroup
import com.tencent.devops.auth.pojo.action.ActionInfo
import com.tencent.devops.auth.pojo.dto.ProjectRoleDTO
import com.tencent.devops.auth.pojo.vo.GroupInfoVo
import com.tencent.devops.common.api.auth.AUTH_HEADER_USER_ID
import com.tencent.devops.common.api.pojo.Result
import io.swagger.annotations.Api
import io.swagger.annotations.ApiOperation
import io.swagger.annotations.ApiParam
import javax.ws.rs.Consumes
import javax.ws.rs.DELETE
import javax.ws.rs.GET
import javax.ws.rs.HeaderParam
import javax.ws.rs.POST
import javax.ws.rs.PUT
import javax.ws.rs.Path
import javax.ws.rs.PathParam
import javax.ws.rs.Produces
import javax.ws.rs.QueryParam
import javax.ws.rs.core.MediaType

@Api(tags = ["USER_PROJECT_ROLE"], description = "项目-用户组")
@Path("/user/project/roles")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
interface UserProjectRoleResource {
    @POST
    @Path("/projectIds/{projectId}/")
    @ApiOperation("项目下添加指定组")
    fun createProjectRole(
        @ApiParam(name = "用户名", required = true)
        @HeaderParam(AUTH_HEADER_USER_ID)
        userId: String,
        @ApiParam(name = "项目标识", required = true)
        @PathParam("projectId")
        projectId: String,
        @ApiParam("用户组信息", required = true)
        groupInfo: ProjectRoleDTO
    ): Result<String>

    @PUT
    @Path("/projectIds/{projectId}/roleIds/{roleId}")
    @ApiOperation("用户组重命名")
    fun updateProjectRole(
        @ApiParam(name = "用户名", required = true)
        @HeaderParam(AUTH_HEADER_USER_ID)
        userId: String,
        @ApiParam(name = "项目标识", required = true)
        @PathParam("projectId")
        projectId: String,
        @ApiParam(name = "角色Id", required = true)
        @PathParam("roleId")
        roleId: Int,
        @ApiParam(name = "用户组信息", required = true)
        groupInfo: ProjectRoleDTO
    ): Result<Boolean>

    @PUT
    @Path("/projectIds/{projectId}/roleIds/{roleId}/desc")
    @ApiOperation("用户组重命名")
    fun updateGroupDesc(
        @ApiParam(name = "用户名", required = true)
        @HeaderParam(AUTH_HEADER_USER_ID)
        userId: String,
        @ApiParam(name = "项目标识", required = true)
        @PathParam("projectId")
        projectId: String,
        @ApiParam(name = "角色Id", required = true)
        @PathParam("roleId")
        roleId: Int,
        @ApiParam(name = "描述", required = true)
        desc: String
    ): Result<Boolean>

    @GET
    @Path("/projectIds/{projectId}")
    @ApiOperation("获取用户组")
    fun getProjectRoles(
        @ApiParam(name = "用户名", required = true)
        @HeaderParam(AUTH_HEADER_USER_ID)
        userId: String,
        @ApiParam(name = "项目标识", required = true)
        @PathParam("projectId")
        projectId: String
    ): Result<List<GroupInfoVo>>

    @DELETE
    @Path("/projectIds/{projectId}/roles/{roleId}")
    @ApiOperation("删除用户组")
    fun deleteProjectRole(
        @ApiParam(name = "用户名", required = true)
        @HeaderParam(AUTH_HEADER_USER_ID)
        userId: String,
        @ApiParam(name = "项目标识", required = true)
        @PathParam("projectId")
        projectId: String,
        @ApiParam(name = "角色Id", required = true)
        @PathParam("roleId")
        roleId: Int
    ): Result<Boolean>

    @GET
    @Path("/projects/{projectId}/manager/hasPermission")
    @ApiOperation("是否有项目管理操作的权限")
    fun hashPermission(
        @ApiParam(name = "用户名", required = true)
        @HeaderParam(AUTH_HEADER_USER_ID)
        userId: String,
        @ApiParam(name = "项目标识", required = true)
        @PathParam("projectId")
        projectId: String
    ): Result<Boolean>

    @POST
    @Path("/{roleId}/projectCodes/{projectCode}/permission/strategy")
    @ApiOperation("分配自定义用户组权限")
    fun setRolePermissionStrategy(
        @ApiParam(name = "用户名", required = true)
        @HeaderParam(AUTH_HEADER_USER_ID)
        userId: String,
        @ApiParam(name = "项目标识", required = true)
        @PathParam("projectCode")
        projectCode: String,
        @ApiParam(name = "角色Id", required = true)
        @PathParam("roleId")
        roleId: Int,
        @ApiParam(name = "权限信息", required = true)
        strategy: Map<String, List<String>>
    ): Result<Boolean>

    @PUT
    @Path("/{roleId}/projectCodes/{projectCode}/permission/strategy")
    @ApiOperation("修改自定义用户组权限")
    fun updateRolePermissionStrategy(
        @ApiParam(name = "用户名", required = true)
        @HeaderParam(AUTH_HEADER_USER_ID)
        userId: String,
        @ApiParam(name = "项目标识", required = true)
        @PathParam("projectCode")
        projectCode: String,
        @ApiParam(name = "角色Id", required = true)
        @PathParam("roleId")
        roleId: Int,
        @ApiParam(name = "权限信息", required = true)
        strategy: Map<String, List<String>>
    ): Result<Boolean>

    @GET
    @Path("/{roleId}/projectCodes/{projectCode}/permission/strategy")
    fun getRolePermissionStrategy(
        @ApiParam(name = "用户名", required = true)
        @HeaderParam(AUTH_HEADER_USER_ID)
        userId: String,
        @ApiParam(name = "项目标识", required = true)
        @PathParam("projectCode")
        projectCode: String,
        @ApiParam(name = "角色Id", required = true)
        @PathParam("roleId")
        roleId: Int
    ): Result<Map<String, List<ActionInfo>>>

    @GET
    @Path("/default/role")
    fun getDefaultRole(
        @ApiParam(name = "用户名", required = true)
        @HeaderParam(AUTH_HEADER_USER_ID)
        userId: String
    ): Result<List<DefaultGroup>>
}
