use crate::sql_backend_handler::SqlBackendHandler;
use async_trait::async_trait;
use lldap_domain::{
    requests::CreateAttributeRequest,
    schema::{AttributeList, AttributeSchema, Schema},
    types::{AttributeName, LdapObjectClass},
};
use lldap_domain_handlers::handler::{ReadSchemaBackendHandler, SchemaBackendHandler};
use lldap_domain_model::{
    error::{DomainError, Result},
    model,
};
use sea_orm::{
    ActiveModelTrait, DatabaseTransaction, EntityTrait, QueryOrder, Set, TransactionTrait,
};
use tracing::debug;

#[async_trait]
impl ReadSchemaBackendHandler for SqlBackendHandler {
    async fn get_schema(&self) -> Result<Schema> {
        Ok(self
            .sql_pool
            .transaction::<_, Schema, DomainError>(|transaction| {
                Box::pin(async move { Self::get_schema_with_transaction(transaction).await })
            })
            .await?)
    }
}

#[async_trait]
impl SchemaBackendHandler for SqlBackendHandler {
    async fn add_user_attribute(&self, request: CreateAttributeRequest) -> Result<()> {
        let new_attribute = model::user_attribute_schema::ActiveModel {
            attribute_name: Set(request.name),
            attribute_type: Set(request.attribute_type),
            is_list: Set(request.is_list),
            is_user_visible: Set(request.is_visible),
            is_user_editable: Set(request.is_editable),
            is_hardcoded: Set(false),
        };
        new_attribute.insert(&self.sql_pool).await?;
        Ok(())
    }

    async fn add_group_attribute(&self, request: CreateAttributeRequest) -> Result<()> {
        let new_attribute = model::group_attribute_schema::ActiveModel {
            attribute_name: Set(request.name),
            attribute_type: Set(request.attribute_type),
            is_list: Set(request.is_list),
            is_group_visible: Set(request.is_visible),
            is_group_editable: Set(request.is_editable),
            is_hardcoded: Set(false),
        };
        new_attribute.insert(&self.sql_pool).await?;
        Ok(())
    }

    async fn delete_user_attribute(&self, name: &AttributeName) -> Result<()> {
        model::UserAttributeSchema::delete_by_id(name.clone())
            .exec(&self.sql_pool)
            .await?;
        Ok(())
    }

    async fn delete_group_attribute(&self, name: &AttributeName) -> Result<()> {
        model::GroupAttributeSchema::delete_by_id(name.clone())
            .exec(&self.sql_pool)
            .await?;
        Ok(())
    }

    async fn add_user_object_class(&self, name: &LdapObjectClass) -> Result<()> {
        let mut name_key = name.to_string();
        name_key.make_ascii_lowercase();
        model::user_object_classes::ActiveModel {
            lower_object_class: Set(name_key),
            object_class: Set(name.clone()),
        }
        .insert(&self.sql_pool)
        .await?;
        Ok(())
    }

    async fn add_group_object_class(&self, name: &LdapObjectClass) -> Result<()> {
        let mut name_key = name.to_string();
        name_key.make_ascii_lowercase();
        model::group_object_classes::ActiveModel {
            lower_object_class: Set(name_key),
            object_class: Set(name.clone()),
        }
        .insert(&self.sql_pool)
        .await?;
        Ok(())
    }

    async fn delete_user_object_class(&self, name: &LdapObjectClass) -> Result<()> {
        model::UserObjectClasses::delete_by_id(name.as_str().to_ascii_lowercase())
            .exec(&self.sql_pool)
            .await?;
        Ok(())
    }

    async fn delete_group_object_class(&self, name: &LdapObjectClass) -> Result<()> {
        model::GroupObjectClasses::delete_by_id(name.as_str().to_ascii_lowercase())
            .exec(&self.sql_pool)
            .await?;
        Ok(())
    }
}

impl SqlBackendHandler {
    pub(crate) async fn get_schema_with_transaction(
        transaction: &DatabaseTransaction,
    ) -> Result<Schema> {
        Ok(Schema {
            user_attributes: AttributeList {
                attributes: Self::get_user_attributes(transaction).await?,
            },
            group_attributes: AttributeList {
                attributes: Self::get_group_attributes(transaction).await?,
            },
            extra_user_object_classes: Self::get_user_object_classes(transaction)
            .await?
            .into_iter()
            .map(|oc| oc.into_string())
            .collect(),
           extra_group_object_classes: Self::get_group_object_classes(transaction)
           .await?
           .into_iter()
           .map(|oc| oc.into_string())
           .collect(),
        })
    }

    async fn get_user_attributes(
        transaction: &DatabaseTransaction,
    ) -> Result<Vec<AttributeSchema>> {
        debug!("SCHEMA_TX STEP USER_ATTR 1: START - clean model load (raw bypass removed - AttributeType now SeaORM-native)");
        let raw_models = model::UserAttributeSchema::find()
        .order_by_asc(model::UserAttributeSchemaColumn::AttributeName)
        .all(transaction)
        .await
        .map_err(|e| {
            debug!("SCHEMA_TX STEP USER_ATTR 1 FAILED model query: {:?}", e);
            e
        })?;
        debug!("SCHEMA_TX STEP USER_ATTR 2: SUCCESS - {} raw models returned", raw_models.len());
        let mut result = Vec::with_capacity(raw_models.len());
        for (i, m) in raw_models.into_iter().enumerate() {
            debug!("SCHEMA_TX STEP USER_ATTR 3.{:02} MODEL_ROW: name='{}' | type='{:?}' | is_list={} | visible={} | editable={} | hardcoded={}",
                   i, m.attribute_name, m.attribute_type, m.is_list, m.is_user_visible, m.is_user_editable, m.is_hardcoded);
            let converted = m.into();
            debug!("SCHEMA_TX STEP USER_ATTR 3.{:02}.1 SUCCESS - converted to AttributeSchema (delegates to schema crate)", i);
            result.push(converted);
        }
        debug!("SCHEMA_TX STEP USER_ATTR 4: SUCCESS - returning {} user attributes", result.len());
        Ok(result)
    }

    async fn get_group_attributes(
        transaction: &DatabaseTransaction,
    ) -> Result<Vec<AttributeSchema>> {
        debug!("SCHEMA_TX STEP GROUP_ATTR 1: START - about to query group_attribute_schema");
        let raw_models = model::GroupAttributeSchema::find()
        .order_by_asc(model::GroupAttributeSchemaColumn::AttributeName)
        .all(transaction)
        .await
        .map_err(|e| {
            debug!("SCHEMA_TX STEP GROUP_ATTR 1 FAILED query: {:?}", e);
            e
        })?;
        debug!("SCHEMA_TX STEP GROUP_ATTR 2: raw_models.len() = {}", raw_models.len());
        let mut result = Vec::with_capacity(raw_models.len());
        for (i, m) in raw_models.into_iter().enumerate() {
            debug!("SCHEMA_TX STEP GROUP_ATTR 3.{:02} RAW_DB_ROW: name='{}' | type_string='{:?}' | is_list={} | visible={} | editable={} | hardcoded={}",
                   i, m.attribute_name, m.attribute_type, m.is_list, m.is_group_visible, m.is_group_editable, m.is_hardcoded);
            let converted = m.into();
            debug!("SCHEMA_TX STEP GROUP_ATTR 3.{:02}.1 SUCCESS - converted to AttributeSchema", i);
            result.push(converted);
        }
        debug!("SCHEMA_TX STEP GROUP_ATTR 4: SUCCESS - returning {} group attributes", result.len());
        Ok(result)
    }

    async fn get_user_object_classes(
        transaction: &DatabaseTransaction,
    ) -> Result<Vec<LdapObjectClass>> {
        Ok(model::UserObjectClasses::find()
            .order_by_asc(model::UserObjectClassesColumn::ObjectClass)
            .all(transaction)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    async fn get_group_object_classes(
        transaction: &DatabaseTransaction,
    ) -> Result<Vec<LdapObjectClass>> {
        Ok(model::GroupObjectClasses::find()
            .order_by_asc(model::GroupObjectClassesColumn::ObjectClass)
            .all(transaction)
            .await?
            .into_iter()
            .map(Into::into)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql_backend_handler::tests::*;
    use lldap_domain::requests::UpdateUserRequest;
    use lldap_domain::schema::AttributeList;
    use lldap_domain::types::{Attribute, AttributeType};
    use lldap_domain_handlers::handler::{UserBackendHandler, UserRequestFilter};
    use pretty_assertions::assert_eq;

    #[tokio::test]
    async fn test_default_schema() {
        let fixture = TestFixture::new().await;
        assert_eq!(
            fixture.handler.get_schema().await.unwrap(),
            Schema {
                user_attributes: AttributeList {
                    attributes: vec![
                        AttributeSchema {
                            name: "avatar".into(),
                            attribute_type: AttributeType::JpegPhoto,
                            is_list: false,
                            is_visible: true,
                            is_editable: true,
                            is_hardcoded: true,
                            is_readonly: false,
                        },
                        AttributeSchema {
                            name: "first_name".into(),
                            attribute_type: AttributeType::String,
                            is_list: false,
                            is_visible: true,
                            is_editable: true,
                            is_hardcoded: true,
                            is_readonly: false,
                        },
                        AttributeSchema {
                            name: "last_name".into(),
                            attribute_type: AttributeType::String,
                            is_list: false,
                            is_visible: true,
                            is_editable: true,
                            is_hardcoded: true,
                            is_readonly: false,
                        }
                    ]
                },
                group_attributes: AttributeList {
                    attributes: Vec::new()
                },
                extra_user_object_classes: Vec::new(),
                extra_group_object_classes: Vec::new(),
            }
        );
    }

    #[tokio::test]
    async fn test_user_attribute_add_and_delete() {
        let fixture = TestFixture::new().await;
        let new_attribute = CreateAttributeRequest {
            name: "new_attribute".into(),
            attribute_type: AttributeType::Integer,
            is_list: true,
            is_visible: false,
            is_editable: false,
        };
        fixture
            .handler
            .add_user_attribute(new_attribute)
            .await
            .unwrap();
        let expected_value = AttributeSchema {
            name: "new_attribute".into(),
            attribute_type: AttributeType::Integer,
            is_list: true,
            is_visible: false,
            is_editable: false,
            is_hardcoded: false,
            is_readonly: false,
        };
        assert!(
            fixture
                .handler
                .get_schema()
                .await
                .unwrap()
                .user_attributes
                .attributes
                .contains(&expected_value)
        );
        fixture
            .handler
            .delete_user_attribute(&"new_attribute".into())
            .await
            .unwrap();
        assert!(
            !fixture
                .handler
                .get_schema()
                .await
                .unwrap()
                .user_attributes
                .attributes
                .contains(&expected_value)
        );
    }

    #[tokio::test]
    async fn test_user_attribute_present_filter() {
        let fixture = TestFixture::new().await;
        let new_attribute = CreateAttributeRequest {
            name: "new_attribute".into(),
            attribute_type: AttributeType::Integer,
            is_list: true,
            is_visible: false,
            is_editable: false,
        };
        fixture
            .handler
            .add_user_attribute(new_attribute)
            .await
            .unwrap();
        fixture
            .handler
            .update_user(UpdateUserRequest {
                user_id: "bob".into(),
                insert_attributes: vec![Attribute {
                    name: "new_attribute".into(),
                    value: vec![3].into(),
                }],
                ..Default::default()
            })
            .await
            .unwrap();
        let users = get_user_names(
            &fixture.handler,
            Some(UserRequestFilter::CustomAttributePresent(
                "new_attribute".into(),
            )),
        )
        .await;
        assert_eq!(users, vec!["bob"]);
    }

    #[tokio::test]
    async fn test_group_attribute_add_and_delete() {
        let fixture = TestFixture::new().await;
        let new_attribute = CreateAttributeRequest {
            name: "NeW_aTTribute".into(),
            attribute_type: AttributeType::JpegPhoto,
            is_list: false,
            is_visible: true,
            is_editable: false,
        };
        fixture
            .handler
            .add_group_attribute(new_attribute)
            .await
            .unwrap();
        let expected_value = AttributeSchema {
            name: "new_attribute".into(),
            attribute_type: AttributeType::JpegPhoto,
            is_list: false,
            is_visible: true,
            is_editable: false,
            is_hardcoded: false,
            is_readonly: false,
        };
        assert!(
            fixture
                .handler
                .get_schema()
                .await
                .unwrap()
                .group_attributes
                .attributes
                .contains(&expected_value)
        );
        fixture
            .handler
            .delete_group_attribute(&"new_attriBUte".into())
            .await
            .unwrap();
        assert!(
            !fixture
                .handler
                .get_schema()
                .await
                .unwrap()
                .group_attributes
                .attributes
                .contains(&expected_value)
        );
    }

    #[tokio::test]
    async fn test_user_object_class_add_and_delete() {
        let fixture = TestFixture::new().await;
        let new_object_class = LdapObjectClass::new("newObjectClass");
        fixture
            .handler
            .add_user_object_class(&new_object_class)
            .await
            .unwrap();
        assert_eq!(
            fixture
                .handler
                .get_schema()
                .await
                .unwrap()
                .extra_user_object_classes,
            vec![new_object_class.clone()]
        );
        fixture
            .handler
            .add_user_object_class(&LdapObjectClass::new("newobjEctclass"))
            .await
            .expect_err("Should not be able to add the same object class twice");
        assert_eq!(
            fixture
                .handler
                .get_schema()
                .await
                .unwrap()
                .extra_user_object_classes,
            vec![new_object_class.clone()]
        );
        fixture
            .handler
            .delete_user_object_class(&new_object_class)
            .await
            .unwrap();
        assert!(
            fixture
                .handler
                .get_schema()
                .await
                .unwrap()
                .extra_user_object_classes
                .is_empty()
        );
    }
}
