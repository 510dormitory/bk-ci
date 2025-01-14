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

package com.tencent.devops.process.dao.label

import com.tencent.devops.model.process.tables.TPipelineGroup
import com.tencent.devops.model.process.tables.TPipelineLabel
import com.tencent.devops.model.process.tables.TPipelineLabelPipeline
import com.tencent.devops.model.process.tables.records.TPipelineLabelPipelineRecord
import org.jooq.DSLContext
import org.jooq.Record3
import org.jooq.Result
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Repository
import java.time.LocalDateTime

/**
 * 流水线和标签对应关系表
 */
@Repository
class PipelineLabelPipelineDao {

    fun create(
        dslContext: DSLContext,
        projectId: String,
        pipelineId: String,
        labelId: Long,
        userId: String
    ) {
        logger.info("Create pipeline-label for pipeline $pipelineId with label $labelId by user $userId")
        with(TPipelineLabelPipeline.T_PIPELINE_LABEL_PIPELINE) {
            dslContext.insertInto(
                this,
                PROJECT_ID,
                PIPELINE_ID,
                LABEL_ID,
                CREATE_TIME,
                CREATE_USER
            )
                .values(
                    projectId,
                    pipelineId,
                    labelId,
                    LocalDateTime.now(),
                    userId
                ).onDuplicateKeyIgnore()
                .execute()
        }
    }

    fun batchCreate(
        dslContext: DSLContext,
        projectId: String,
        pipelineId: String,
        labelIds: Set<Long>,
        userId: String
    ) {
        logger.info("Create pipeline-label for pipeline $pipelineId with labels $labelIds by user $userId")
        with(TPipelineLabelPipeline.T_PIPELINE_LABEL_PIPELINE) {
            dslContext.batch(
                labelIds.map {
                    dslContext.insertInto(
                        this,
                        PROJECT_ID,
                        PIPELINE_ID,
                        LABEL_ID,
                        CREATE_TIME,
                        CREATE_USER
                    )
                        .values(
                            projectId,
                            pipelineId,
                            it,
                            LocalDateTime.now(),
                            userId
                        ).onDuplicateKeyIgnore()
                }
            ).execute()
        }
    }

    fun delete(
        dslContext: DSLContext,
        id: Long,
        userId: String
    ) {
        logger.info("Delete pipeline-label $id by user $userId")
        with(TPipelineLabelPipeline.T_PIPELINE_LABEL_PIPELINE) {
            dslContext.deleteFrom(this)
                .where(ID.eq(id))
                .execute()
        }
    }

    fun deleteByPipeline(
        dslContext: DSLContext,
        pipelineId: String,
        userId: String
    ): Int {
        logger.info("Delete pipeline-label of pipeline $pipelineId by user $userId")
        with(TPipelineLabelPipeline.T_PIPELINE_LABEL_PIPELINE) {
            return dslContext.deleteFrom(this)
                .where(PIPELINE_ID.eq(pipelineId))
                .execute()
        }
    }

    fun deleteByLabel(
        dslContext: DSLContext,
        labelId: Long,
        userId: String
    ): Int {
        logger.info("Delete pipeline-label of label $labelId by user $userId")
        with(TPipelineLabelPipeline.T_PIPELINE_LABEL_PIPELINE) {
            return dslContext.deleteFrom(this)
                .where(LABEL_ID.eq(labelId))
                .execute()
        }
    }

    fun listPipelines(
        dslContext: DSLContext,
        labelId: Long
    ): Result<TPipelineLabelPipelineRecord> {
        with(TPipelineLabelPipeline.T_PIPELINE_LABEL_PIPELINE) {
            return dslContext.selectFrom(this)
                .where(LABEL_ID.eq(labelId))
                .fetch()
        }
    }

    fun listPipelines(
        dslContext: DSLContext,
        labelId: Set<Long>
    ): Result<TPipelineLabelPipelineRecord> {
        with(TPipelineLabelPipeline.T_PIPELINE_LABEL_PIPELINE) {
            return dslContext.selectFrom(this)
                .where(LABEL_ID.`in`(labelId))
                .fetch()
        }
    }

    fun listLabels(
        dslContext: DSLContext,
        pipelineId: String
    ): Result<TPipelineLabelPipelineRecord> {
        with(TPipelineLabelPipeline.T_PIPELINE_LABEL_PIPELINE) {
            return dslContext.selectFrom(this)
                .where(PIPELINE_ID.eq(pipelineId))
                .fetch()
        }
    }

    /**
     * 获取Pipelines的group与label
     */
    fun listPipelinesGroupsAndLabels(
        dslContext: DSLContext,
        pipelineIds: List<String>
    ): Result<Record3<String, String, String>> {
        val labelPipelineTable = TPipelineLabelPipeline.T_PIPELINE_LABEL_PIPELINE.`as`("t1")
        val labelTable = TPipelineLabel.T_PIPELINE_LABEL.`as`("t2")
        val groupTable = TPipelineGroup.T_PIPELINE_GROUP.`as`("t3")
        // 排除标签和分组为空的情况
        return dslContext.select(
            labelPipelineTable.PIPELINE_ID.`as`("PIPELINE_ID"),
            groupTable.NAME.`as`("GROUP_NAME"),
            labelTable.NAME.`as`("LABEL_NAME")
        ).from(labelPipelineTable)
            .leftJoin(labelTable)
            .on(labelPipelineTable.LABEL_ID.eq(labelTable.ID))
            .leftJoin(groupTable)
            .on(labelTable.GROUP_ID.eq(groupTable.ID))
            .where(labelPipelineTable.PIPELINE_ID.`in`(pipelineIds))
            .and(labelTable.NAME.notEqual(""))
            .and(labelTable.NAME.isNotNull)
            .and(groupTable.NAME.notEqual(""))
            .and(groupTable.NAME.isNotNull)
            .and(labelPipelineTable.PIPELINE_ID.notEqual(""))
            .and(labelPipelineTable.PIPELINE_ID.isNotNull)
            .fetch()
    }

    /**
     * 获取Pipeline的group与label
     */
    fun listPipelineGroupsAndLabels(
        dslContext: DSLContext,
        pipelineId: String
    ): Result<Record3<String, String, String>> {
        return listPipelinesGroupsAndLabels(dslContext, listOf(pipelineId))
    }

    companion object {
        private val logger = LoggerFactory.getLogger(PipelineLabelPipelineDao::class.java)
    }
}
