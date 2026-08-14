# 表单校验开发规范

前端表单统一使用 `apps/web/src/formValidation.ts` 执行校验，具体规则集中维护在 `apps/web/src/formRules.ts`。

## 基本约定

1. 每个提交表单都必须有独立的 `FormRule`，不能只依赖 HTML `required` 或提交函数中的临时判断。
2. 字段格式、必填条件和跨字段关系写入规则文件；提交函数只负责组装业务 payload 和调用 API。
3. 动态必填项必须同时更新控件的 `required` 或 `Field.requiredMark`，让用户在提交前就能看到红色星号。
4. 涉及部署、安全、资源冲突或数据完整性的规则必须在后端重复校验，前端校验不能作为安全边界。
5. 错误文案直接说明字段和修正方法，不向用户展示内部对象名、堆栈或实现细节。

## 新增表单

在 `formRules.ts` 中声明规则：

```ts
export const exampleFormRule: FormRule = {
  fields: [
    field({ name: "name", label: "名称", required: true }),
  ],
  validate: (values) => {
    return fieldString(values, "name") === "reserved"
      ? [{ field: "name", message: "该名称已被保留，请更换" }]
      : [];
  },
};
```

提交时先执行统一校验：

```ts
const form = validateForm(event.currentTarget, exampleFormRule);
```

规则失败时，执行器会聚合问题、设置 `aria-invalid`、标红对应控件并聚焦第一个错误字段。用户修改字段后，旧错误状态会自动清除。

## 测试要求

规则测试放在 `apps/web/src/formRules.test.ts`，至少覆盖：

- 必填和可选字段。
- 数字范围、IP、CIDR、端口和接口名称格式。
- 根据开关或协议变化的动态规则。
- 两个及以上字段之间的冲突关系。
- 前端规则对应的后端兜底校验。

运行：

```bash
npm test --prefix apps/web
npm run build --prefix apps/web
```
