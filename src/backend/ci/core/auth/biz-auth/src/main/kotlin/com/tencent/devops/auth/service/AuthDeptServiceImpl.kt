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

package com.tencent.devops.auth.service

import com.fasterxml.jackson.databind.ObjectMapper
import com.google.common.cache.CacheBuilder
import com.tencent.bk.sdk.iam.dto.response.ResponseDTO
import com.tencent.bk.sdk.iam.util.JsonUtil
import com.tencent.devops.auth.common.Constants.DEPT_LABEL
import com.tencent.devops.auth.common.Constants.LEVEL
import com.tencent.devops.auth.common.Constants.PARENT
import com.tencent.devops.auth.common.Constants.HTTP_RESULT
import com.tencent.devops.auth.entity.SearchDeptEntity
import com.tencent.devops.auth.entity.SearchDeptUserEntity
import com.tencent.devops.auth.pojo.vo.DeptInfoVo
import com.tencent.devops.common.api.exception.RemoteServiceException
import com.tencent.devops.common.api.util.OkhttpUtils
import com.tencent.devops.common.auth.api.AuthTokenApi
import com.tencent.devops.common.auth.code.AuthServiceCode
import com.tencent.devops.common.redis.RedisOperation
import okhttp3.MediaType
import okhttp3.Request
import okhttp3.RequestBody
import org.slf4j.LoggerFactory
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Value
import java.util.concurrent.TimeUnit

class AuthDeptServiceImpl @Autowired constructor(
    val redisOperation: RedisOperation,
    val objectMapper: ObjectMapper
) : DeptService {

    @Value("\${esb.code:#{null}}")
    val appCode: String? = null

    @Value("\${esb.secret:#{null}}")
    val appSecret: String? = null

    @Value("\${bk.user.host:#{null}}")
    val bkUserHost: String? = null

    private val deptUserCache = CacheBuilder.newBuilder()
        .maximumSize(500)
        .expireAfterWrite(1, TimeUnit.HOURS)
        .build<String/*deptId*/, List<String>>()

    override fun getDeptByLevel(level: Int, accessToken: String?, userId: String): DeptInfoVo {
        val search = SearchDeptEntity(
            bk_app_code = appCode!!,
            bk_app_secret = appSecret!!,
            bk_username = userId,
            fields = DEPT_LABEL,
            lookupField = LEVEL,
            exactLookups = level,
            fuzzyLookups = null,
            accessToken = accessToken
        )
        return getDeptInfo(search)
    }

    override fun getDeptByParent(parentId: Int, accessToken: String?, userId: String, pageSize: Int?): DeptInfoVo {
        val search = SearchDeptEntity(
            bk_app_code = appCode!!,
            bk_app_secret = appSecret!!,
            bk_username = userId,
            fields = DEPT_LABEL,
            lookupField = PARENT,
            exactLookups = parentId,
            fuzzyLookups = null,
            accessToken = accessToken,
            pageSize = pageSize ?: null
        )
        return getDeptInfo(search)
    }

    override fun getDeptUser(deptId: Int, accessToken: String?): List<String> {
        return if (deptUserCache.getIfPresent(deptId.toString()) == null) {
            deptUserCache.getIfPresent(deptId.toString())!!
        } else {
            val deptUsers = getAndRefreshDeptUser(deptId, accessToken)
            deptUserCache.put(deptId.toString(), deptUsers)
            deptUsers
        }
    }

    private fun getAndRefreshDeptUser(deptId: Int, accessToken: String?) : List<String> {
        // TODO: 获取accessToken
        val accessToken = accessToken
        val search = SearchDeptUserEntity(
            id = deptId,
            recursive = true,
            bk_app_code = appCode!!,
            bk_app_secret = appSecret!!,
            bk_username = "",
            accessToken = accessToken
        )
        val url = getAuthRequestUrl(LIST_DEPARTMENT_PROFILES)
        val content = objectMapper.writeValueAsString(search)
        val mediaType = MediaType.parse("application/json; charset=utf-8")
        val requestBody = RequestBody.create(mediaType, content)
        val request = Request.Builder().url(url)
            .post(requestBody)
            .build()
        OkhttpUtils.doHttp(request).use {
            if (!it.isSuccessful) {
                // 请求错误
                throw RemoteServiceException("get dept user fail, response: ($it)")
            }
            val responseStr = it.body()!!.string()
            return findUserName(responseStr)
        }
    }

    private fun getDeptInfo(search: SearchDeptEntity): DeptInfoVo {
        val url = getAuthRequestUrl(LIST_DEPARTMENTS)
        val content = objectMapper.writeValueAsString(search)
        logger.info("getDeptInfo url: $url, body: ${JsonUtil.toJson(search)}")
        val mediaType = MediaType.parse("application/json; charset=utf-8")
        val requestBody = RequestBody.create(mediaType, content)
        val request = Request.Builder().url(url)
            .post(requestBody)
            .build()
        OkhttpUtils.doHttp(request).use {
            if (!it.isSuccessful) {
                // 请求错误
                throw RemoteServiceException("get dept fail, response: ($it)")
            }
            val responseStr = it.body()!!.string()
            val responseDTO = JsonUtil.fromJson(responseStr, ResponseDTO::class.java)
            if (responseDTO.code != 0L || responseDTO.result == false) {
                // 请求错误
                throw RemoteServiceException(
                    "get dept fail: $responseStr"
                )
            }
            return JsonUtil.fromJson(JsonUtil.toJson(responseDTO.data), DeptInfoVo::class.java)
        }
    }

    fun findUserName(str: String): List<String> {
        val responseDTO = JsonUtil.fromJson(str, ResponseDTO::class.java)

        if (responseDTO.code != 0L || responseDTO.result == false) {
            // 请求错误
            throw RemoteServiceException(
                "get dept user fail: $str"
            )
        }
        val responseData = JsonUtil.toJson(responseDTO.data)
        val dataMap =  JsonUtil.fromJson(responseData, Map::class.java)
        val userInfoList = JsonUtil.fromJson(JsonUtil.toJson(dataMap[HTTP_RESULT]), List::class.java)
        val users = mutableListOf<String>()
        userInfoList.forEach {
            val userInfo = JsonUtil.toJson(it)
            val userInfoMap = JsonUtil.fromJson(userInfo, Map::class.java)
            val userName = userInfoMap.get("username").toString()
            users.add(userName)
        }

        return users
    }

    /**
     * 生成请求url
     */
    private fun getAuthRequestUrl(uri: String): String {
        return if (bkUserHost?.endsWith("/")!!) {
            bkUserHost + uri
        } else {
            "$bkUserHost/$uri"
        }
    }

    companion object {
        val logger = LoggerFactory.getLogger(AuthDeptServiceImpl::class.java)
        const val LIST_DEPARTMENTS = "api/c/compapi/v2/usermanage/list_departments/"
        const val LIST_DEPARTMENT_PROFILES = "api/c/compapi/v2/usermanage/list_department_profiles/"
    }
}