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

package com.tencent.devops.auth.service.iam.impl

import com.tencent.bk.sdk.iam.config.IamConfiguration
import com.tencent.bk.sdk.iam.dto.PageInfoDTO
import com.tencent.bk.sdk.iam.dto.manager.Action
import com.tencent.bk.sdk.iam.dto.manager.AuthorizationScopes
import com.tencent.bk.sdk.iam.dto.manager.ManagerPath
import com.tencent.bk.sdk.iam.dto.manager.ManagerResources
import com.tencent.bk.sdk.iam.dto.manager.ManagerRoleGroup
import com.tencent.bk.sdk.iam.dto.manager.dto.ManagerRoleGroupDTO
import com.tencent.bk.sdk.iam.exception.IamException
import com.tencent.bk.sdk.iam.service.ManagerService
import com.tencent.devops.auth.constant.AuthMessageCode
import com.tencent.devops.auth.dao.AuthGroupDao
import com.tencent.devops.auth.pojo.DefaultGroup
import com.tencent.devops.auth.pojo.dto.ProjectRoleDTO
import com.tencent.devops.auth.pojo.vo.GroupInfoVo
import com.tencent.devops.auth.service.AuthCustomizePermissionService
import com.tencent.devops.auth.service.AuthGroupService
import com.tencent.devops.auth.service.StrategyService
import com.tencent.devops.auth.service.action.ActionService
import com.tencent.devops.auth.service.action.BkResourceService
import com.tencent.devops.auth.service.ci.impl.AbsPermissionRoleMemberImpl
import com.tencent.devops.auth.service.ci.impl.AbsPermissionRoleServiceImpl
import com.tencent.devops.auth.service.iam.IamCacheService
import com.tencent.devops.auth.service.iam.PermissionGradeService
import com.tencent.devops.common.api.exception.ErrorCodeException
import com.tencent.devops.common.api.exception.ParamBlankException
import com.tencent.devops.common.api.exception.RemoteServiceException
import com.tencent.devops.common.auth.api.AuthPermission
import com.tencent.devops.common.auth.api.AuthResourceType
import com.tencent.devops.common.auth.api.pojo.BkAuthGroup
import com.tencent.devops.common.auth.api.pojo.DefaultGroupType
import com.tencent.devops.common.auth.utils.IamGroupUtils
import com.tencent.devops.common.client.Client
import com.tencent.devops.common.service.utils.MessageCodeUtil
import com.tencent.devops.project.api.service.ServiceProjectResource
import org.jooq.DSLContext
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired

open class IamPermissionRoleExtService @Autowired constructor(
    open val iamManagerService: ManagerService,
    open val iamCacheService: IamCacheService,
    open val resourceService: BkResourceService,
    open val actionsService: ActionService,
    private val permissionGradeService: PermissionGradeService,
    private val iamConfiguration: IamConfiguration,
    private val groupService: AuthGroupService,
    private val groupDao: AuthGroupDao,
    private val dslContext: DSLContext,
    private val client: Client,
    private val strategyService: StrategyService,
    private val authCustomizePermissionService: AuthCustomizePermissionService
) : AbsPermissionRoleServiceImpl(
    groupService = groupService,
    resourceService = resourceService,
    actionsService = actionsService,
    authCustomizePermissionService = authCustomizePermissionService,
    permissionGradeService = permissionGradeService,
    strategyService = strategyService
) {

    override fun createPermissionRole(
        userId: String,
        projectId: String,
        groupInfo: ProjectRoleDTO,
    ): Int {
        val roleId = super.createPermissionRole(userId, projectId, groupInfo)
        // 扩展添加IAM用户组
        try {
            createIamGroup(
                projectId = projectId,
                roleId = roleId,
                userId = userId,
                groupInfo = groupInfo
            )
        } catch (iamException: IamException) {
            logger.warn("create Role ext fail $iamException")
            groupService.deleteGroup(roleId, false)
            throw RemoteServiceException("create project role fail: ${iamException.errorMsg}")
        } catch (e: Exception) {
            logger.warn("create Role ext fail $e")
            groupService.deleteGroup(roleId, false)
            throw ParamBlankException("create project role fail")
        }
        return roleId
    }

    override fun updatePermissionRole(userId: String, projectId: String, roleId: Int, groupInfo: ProjectRoleDTO) {
        super.updatePermissionRole(userId, projectId, roleId, groupInfo)
        updateIamGroup(userId, projectId, roleId, groupInfo)
    }

    override fun deletePermissionRole(userId: String, projectId: String, roleId: Int) {
        super.deletePermissionRole(userId, projectId, roleId)
        val iamProjectId = iamCacheService.getProjectIamRelationId(projectId)
        deleteIamRole(userId, projectId, iamProjectId)
    }

    override fun getPermissionRole(projectId: String): List<GroupInfoVo> {
        val iamProjectId = iamCacheService.getProjectIamRelationId(projectId)
        val pageInfoDTO = PageInfoDTO()
        pageInfoDTO.limit = 1000
        pageInfoDTO.offset = 0
        val groupInfos = iamManagerService.getGradeManagerRoleGroup(iamProjectId, pageInfoDTO) ?: return emptyList()
        val iamIds = groupInfos.results.map { it.id }
        val localGroupInfo = groupDao.getGroupByRelationIds(dslContext, iamIds)
        val resultList = mutableListOf<GroupInfoVo>()
        localGroupInfo.forEach {
            resultList.add(
                GroupInfoVo(
                    id = it?.id ?: 0,
                    name = it?.groupName ?: "",
                    displayName = it?.displayName ?: "",
                    code = it?.groupCode ?: "",
                    defaultRole = it?.groupType ?: true,
                    userCount = 0,
                    desc = it?.desc ?: ""
                )
            )
        }
        return resultList
    }

    override fun getDefaultRole(): List<DefaultGroup> {
        return emptyList()
    }

    override fun updateRolePermissionStrategy(
        userId: String,
        projectCode: String,
        roleId: Int,
        permissionStrategy: Map<String, List<String>>,
    ): Boolean {
        return super.updateRolePermissionStrategy(userId, projectCode, roleId, permissionStrategy)
    }

    override fun rolePermissionStrategyExt(
        userId: String,
        projectCode: String,
        roleId: Int,
        permissionStrategy: Map<String, List<String>>
    ): Boolean {
        val iamGroupId = groupService.getRelationId(roleId) ?: throw ErrorCodeException(
            errorCode = AuthMessageCode.CAN_NOT_FIND_RELATION,
            defaultMessage = MessageCodeUtil.getCodeLanMessage(AuthMessageCode.CAN_NOT_FIND_RELATION)
        )
        try {
            // TODO: 添加自定义组权限。 待严格测试
            val groupAction = buildGroupAction(permissionStrategy)
            addIamGroupPermission(groupAction, iamGroupId.toInt(), projectCode)
        } catch (iamE: IamException) {
            logger.warn("$projectCode $roleId $permissionStrategy bind iam permission fail: $iamE")
            return false
        } catch (e: Exception) {
            logger.warn("$projectCode $roleId $permissionStrategy bind iam permission fail: $e")
            return false
        }
        return true
    }

    private fun addDevelopPermission(roleId: Int, projectCode: String) {
        addIamGroupAction(roleId, projectCode, DefaultGroupType.DEVELOPER)
    }

    private fun addTestPermission(roleId: Int, projectCode: String) {
        val actions = mutableListOf<String>()
        addIamGroupAction(roleId, projectCode, DefaultGroupType.TESTER)
    }

    private fun addPMPermission(roleId: Int, projectCode: String) {
        addIamGroupAction(roleId, projectCode, DefaultGroupType.PM)
    }

    private fun addQCPermission(roleId: Int, projectCode: String) {
        addIamGroupAction(roleId, projectCode, DefaultGroupType.QC)
    }

    private fun addMaintainerPermission(roleId: Int, projectCode: String) {
        addIamGroupAction(roleId, projectCode, DefaultGroupType.MAINTAINER)
    }

    private fun addIamGroupAction(
        roleId: Int,
        projectCode: String,
        group: DefaultGroupType
    ) {
        val actions = getGroupStrategy(group)
        addIamGroupPermission(actions, roleId, projectCode)
    }

    private fun addIamGroupPermission(
        actions: Pair<List<String>, Map<String, List<String>>>,
        roleId: Int,
        projectCode: String
    ) {
        if (actions.first.isNotEmpty()) {
            val authorizationScopes = buildCreateAuthorizationScopes(actions.first, projectCode)
            iamManagerService.createRolePermission(roleId, authorizationScopes)
        }
        if (actions.second.isNotEmpty()) {
            actions.second.forEach { (resource, actions) ->
                val groupAuthorizationScopes = buildOtherAuthorizationScopes(actions, projectCode, resource)
                iamManagerService.createRolePermission(roleId, groupAuthorizationScopes)
            }
        }
    }

    private fun getGroupStrategy(defaultGroup: DefaultGroupType): Pair<List<String>, Map<String, List<String>>> {
        val strategyInfo = strategyService.getStrategyByName(defaultGroup.displayName)
            ?: throw ErrorCodeException(
                errorCode = AuthMessageCode.STRATEGT_NAME_NOT_EXIST,
                defaultMessage = MessageCodeUtil.getCodeMessage(
                    messageCode = AuthMessageCode.STRATEGT_NAME_NOT_EXIST,
                    params = arrayOf(defaultGroup.value)
                )
            )
        logger.info("getGroupStrategy ${strategyInfo.strategy}")
        return buildGroupAction(strategyInfo.strategy)
    }

    private fun buildGroupAction(actions: Map<String, List<String>>): Pair<List<String>, Map<String, List<String>>> {
        val projectStrategyList = mutableListOf<String>()
        val resourceStrategyMap = mutableMapOf<String, List<String>>()
        actions.forEach { resource, list ->
            val actionData = buildAction(resource, list)
            projectStrategyList.addAll(actionData.first)
            resourceStrategyMap.putAll(actionData.second)
        }
        return Pair(projectStrategyList, resourceStrategyMap)
    }

    private fun buildCreateAuthorizationScopes(actions: List<String>, projectCode: String): AuthorizationScopes {
        val projectInfo = client.get(ServiceProjectResource::class).get(projectCode).data
        val managerResources = mutableListOf<ManagerResources>()
        val managerPath = mutableListOf<ManagerPath>()
        val projectPath = ManagerPath(
            iamConfiguration.systemId,
            AuthResourceType.PROJECT.value,
            projectCode,
            projectInfo?.projectName ?: ""
        )
        managerPath.add(projectPath)
        val paths = mutableListOf<List<ManagerPath>>()
        paths.add(managerPath)
        managerResources.add(
            ManagerResources.builder()
                .system(iamConfiguration.systemId)
                .type(AuthResourceType.PROJECT.value)
                .paths(paths).build()
        )
        val action = mutableListOf<Action>()
        actions.forEach {
            action.add(Action(it))
        }
        return AuthorizationScopes.builder()
            .system(iamConfiguration.systemId)
            .actions(action)
            .resources(managerResources)
            .build()
    }

    private fun buildOtherAuthorizationScopes(
        actions: List<String>,
        projectCode: String,
        defaultType: String? = null
    ): AuthorizationScopes? {
        val projectInfo = client.get(ServiceProjectResource::class).get(projectCode).data

        val resourceTypes = mutableSetOf<String>()
        var type = ""
        actions.forEach {
            resourceTypes.add(it.substringBeforeLast("_"))
            type = it.substringBeforeLast("_")
        }

        if (resourceTypes.size > 1) {
            logger.warn("buildOtherAuthorizationScopes not same resourceType:$resourceTypes")
            return null
        }
        val managerResources = mutableListOf<ManagerResources>()
        val managerPath = mutableListOf<ManagerPath>()
        val projectPath = ManagerPath(
            iamConfiguration.systemId,
            AuthResourceType.PROJECT.value,
            projectCode,
            projectInfo?.projectName ?: ""
        )

        val iamType = if (defaultType.isNullOrEmpty()) {
            AuthResourceType.get(type).value
        } else {
            defaultType
        }

        val resourcePath = ManagerPath(
            iamConfiguration.systemId,
            iamType,
            "*",
            ""
        )
        managerPath.add(projectPath)
        managerPath.add(resourcePath)
        val paths = mutableListOf<List<ManagerPath>>()
        paths.add(managerPath)
        managerResources.add(
            ManagerResources.builder()
                .system(iamConfiguration.systemId)
                .type(iamType)
                .paths(paths).build()
        )
        val action = mutableListOf<Action>()
        actions.forEach {
            action.add(Action(it))
        }
        return AuthorizationScopes.builder()
            .system(iamConfiguration.systemId)
            .actions(action)
            .resources(managerResources)
            .build()
    }

    private fun buildAction(resource: String, actionList: List<String>): Pair<List<String>, Map<String, List<String>>> {
        val projectStrategyList = mutableListOf<String>()
        val resourceStrategyMap = mutableMapOf<String, List<String>>()
        val resourceStrategyList = mutableListOf<String>()
        // 如果是project相关的资源, 直接拼接action
        if (resource == AuthResourceType.PROJECT.value) {
            actionList.forEach { projectAction ->
                projectStrategyList.add(projectAction)
            }
        } else {
            actionList.forEach {
                // 如果是非project资源。 若action包含create,需挂在project下,因create相关的资源都是绑定在项目下。
                if (it.contains(AuthPermission.CREATE.value)) {
                    projectStrategyList.add(it)
                } else {
                    resourceStrategyList.add(it)
                }
            }
            resourceStrategyMap[resource] = resourceStrategyList
            logger.info("$resource $resourceStrategyList")
        }
        return Pair(projectStrategyList, resourceStrategyMap)
    }

    private fun createIamGroup(
        projectId: String,
        roleId: Int,
        groupInfo: ProjectRoleDTO,
        userId: String
    ) {
        val iamProjectId = iamCacheService.getProjectIamRelationId(projectId)

        val defaultGroup = groupInfo.defaultGroup!!

        // 默认分组名称规则: projectName-groupName
        val groupName = IamGroupUtils.buildIamGroup(groupInfo.projectName, groupInfo.displayName ?: groupInfo.name)

        val groupDescription = if (groupInfo.description.isNullOrEmpty()) {
            IamGroupUtils.buildDefaultDescription(groupInfo.projectName, groupInfo.name, userId)
        } else {
            groupInfo.description
        }
        // 添加项目下用户组
        val managerRoleGroup = ManagerRoleGroup(groupName, groupDescription, groupInfo.defaultGroup)
        val roleGroups = mutableListOf<ManagerRoleGroup>()
        roleGroups.add(managerRoleGroup)
        val groups = ManagerRoleGroupDTO.builder().groups(roleGroups).build()
        val iamRoleId = iamManagerService.batchCreateRoleGroup(iamProjectId, groups)

        try {
            // 默认分组需要分配默认权限
            if (defaultGroup) {
                when (groupInfo.code) {
                    BkAuthGroup.DEVELOPER.value -> addDevelopPermission(iamRoleId, projectId)
                    BkAuthGroup.MAINTAINER.value -> addMaintainerPermission(iamRoleId, projectId)
                    BkAuthGroup.TESTER.value -> addTestPermission(iamRoleId, projectId)
                    BkAuthGroup.QC.value -> addQCPermission(iamRoleId, projectId)
                    BkAuthGroup.PM.value -> addPMPermission(iamRoleId, projectId)
                }
            } else {
                // TODO: 添加自定义组权限。 待严格测试
                if (!groupInfo.actionMap.isNullOrEmpty()) {
                    val groupAction = buildGroupAction(groupInfo.actionMap!!)
                    addIamGroupPermission(groupAction, roleId, projectId)
                }
            }
        } catch (e: Exception) {
            iamManagerService.deleteRoleGroup(iamRoleId)
            logger.warn("create iam group permission fail $projectId | $iamRoleId | $groupInfo")
            throw e
        }
        logger.info("create ext group success $projectId $roleId $iamRoleId. start binding")
        // 绑定iamRoleId到本地group表内
        groupService.bindRelationId(roleId, iamRoleId.toString())
    }


    private fun updateIamGroup(userId: String, projectId: String, roleId: Int, groupInfo: ProjectRoleDTO) {
        val iamGroupId = groupService.getRelationId(roleId) ?: return
        permissionGradeService.checkGradeManagerUser(userId, projectId)

        val roleName = IamGroupUtils.buildIamGroup(groupInfo.projectName, groupInfo.name)
        val newGroupInfo = ManagerRoleGroup(
            roleName,
            groupInfo.description,
            groupInfo.defaultGroup
        )
        iamManagerService.updateRoleGroup(iamGroupId.toInt(), newGroupInfo)
    }

    private fun deleteIamRole(userId: String, projectId: String, relationRoleId: Int) {
        logger.info("deleteRoleExt $userId $projectId $relationRoleId")
        val iamProjectId = iamCacheService.getProjectIamRelationId(projectId)
        permissionGradeService.checkGradeManagerUser(userId, projectId)

        // iam侧会统一把用户组内用剔除后,再删除用户组
        iamManagerService.deleteRoleGroup(relationRoleId)
    }

    companion object {
        private val logger = LoggerFactory.getLogger(AbsPermissionRoleMemberImpl::class.java)
        const val PROJECT = "project_view"
        const val PIPELINEACTION = "pipeline_create"
        const val CREDENTIALACTION = "credential_create"
        const val CERTACTION = "cert_create"
        const val REPERTORYACTION = "repertory_create"
        const val ENVIRONMENTACTION = "environment_create"
        const val NODEACTION = "env_node_create"
        const val RULECREATEACTION = "rule_create"
        const val GROUPCREATEACTION = "quality_group_create"
        const val RULEACTION = "rule_delete,rule_edit,rule_enable"
        const val GROUPACTION = "quality_group_delete,quality_group_edit"
    }
}
