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

package com.tencent.devops.auth.service.action.impl

import com.google.common.cache.CacheBuilder
import com.tencent.devops.auth.constant.AuthMessageCode
import com.tencent.devops.auth.dao.ActionDao
import com.tencent.devops.auth.pojo.action.ActionInfo
import com.tencent.devops.auth.pojo.action.CreateActionDTO
import com.tencent.devops.auth.pojo.action.UpdateActionDTO
import com.tencent.devops.auth.service.action.ActionService
import com.tencent.devops.auth.service.action.BkResourceService
import com.tencent.devops.common.api.exception.ErrorCodeException
import com.tencent.devops.common.api.util.DateTimeUtil
import com.tencent.devops.common.auth.api.pojo.DefaultGroupType
import com.tencent.devops.common.service.utils.MessageCodeUtil
import org.jooq.DSLContext
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import java.util.concurrent.TimeUnit

abstract class BKActionServiceImpl @Autowired constructor(
    open val dslContext: DSLContext,
    open val actionDao: ActionDao,
    open val resourceService: BkResourceService
) : ActionService {

    /**
     * 系统action缓存
     */
    private val actionMap = CacheBuilder.newBuilder()
        .expireAfterWrite(1, TimeUnit.HOURS)
        .maximumSize(200)
        .build<String, List<String>>()

    override fun createAction(userId: String, action: CreateActionDTO): Boolean {
        logger.info("createAction $userId|$action")
        val actionId = action.actionId
        val resourceId = action.resourceId

        // 优先判断action挂靠资源是否存在
        resourceService.getResource(resourceId) ?: throw ErrorCodeException(
            errorCode = AuthMessageCode.RESOURCE_NOT_EXSIT,
            params = arrayOf(action.resourceId)
        )

        // action重复性校验
        val actionInfo = actionDao.getAction(dslContext, actionId, "RESOURCEID")
        if (actionInfo != null) {
            throw ErrorCodeException(
                errorCode = AuthMessageCode.ACTION_EXIST,
                params = arrayOf(action.actionId)
            )
        }

        try {
            actionDao.createAction(dslContext, action, userId)
            // 添加扩展系统权限
            extSystemCreate(userId, action)
            return true
        } catch (e: Exception) {
            logger.warn("create action fail $userId|$action|$e")
            actionDao.deleteAction(dslContext, actionId)
            throw ErrorCodeException(
                errorCode = AuthMessageCode.ACTION_CREATE_FAIL
            )
        }
    }

    override fun updateAction(userId: String, actionId: String, action: UpdateActionDTO): Boolean {
        logger.info("updateAction $userId|$actionId|$action")
        actionDao.getAction(dslContext, actionId, "RESOURCEID")
            ?: throw ErrorCodeException(
                errorCode = AuthMessageCode.RESOURCE_NOT_EXSIT,
                params = arrayOf(action.resourceId)
            )
        actionDao.updateAction(dslContext, action, actionId, userId)
        return true
    }

    override fun getAction(actionId: String): ActionInfo? {
        return actionDao.getAction(dslContext, actionId, "*")
    }

    override fun getActions(actionIds: List<String>): List<ActionInfo>? {
        return actionDao.getActions(dslContext, actionIds)
    }

    override fun actionList(): List<ActionInfo>? {
        return actionDao.getAllAction(dslContext, "*")
    }

    override fun actionMap(): Map<String, List<ActionInfo>>? {
        val actionInfos = actionDao.getAllAction(dslContext, "*") ?: return emptyMap()
        val actionMap = mutableMapOf<String, List<ActionInfo>>()
        actionInfos.forEach {
            if (actionMap[it.resourceId] == null) {
                actionMap[it.resourceId] = arrayListOf(it)
            } else {
                val newActionList = mutableListOf<ActionInfo>()
                val actionList = actionMap[it.resourceId]
                newActionList.addAll(actionList!!)
                newActionList.add(it)
                actionMap[it.resourceId] = newActionList
            }
        }
        return actionMap
    }

    override fun checkSystemAction(actions: List<String>): Boolean {
        if (actionMap.getIfPresent(ACTION_MAP_KEY) != null) {
            val systemAction = actionMap.getIfPresent(ACTION_MAP_KEY)
            if (actions.intersect(systemAction!!).size == actions.size) {
                return true
            }
        }
        val systemActions = actionDao.getAllAction(dslContext, "*")?.map {
            it.actionId
        } ?: return false
        if (actions.intersect(systemActions!!).size == actions.size) {
            actionMap.put(ACTION_MAP_KEY, systemActions)
            return true
        }
        return false
    }

    abstract fun extSystemCreate(userId: String, action: CreateActionDTO)

    abstract fun extSystemUpdate(userId: String, actionId: String, action: UpdateActionDTO)

    companion object {
        val logger = LoggerFactory.getLogger(BKActionServiceImpl::class.java)
        const val ACTION_MAP_KEY = "ci"
    }
}
