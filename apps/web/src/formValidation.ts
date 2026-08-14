export type FormValues = Record<string, FormDataEntryValue | FormDataEntryValue[]>;

export type FormValidationIssue = {
  field?: string;
  message: string;
};

export type FormFieldRule<Context = unknown> = {
  name: string;
  label: string;
  required?: boolean | ((values: FormValues, context: Context) => boolean);
  validate?: (
    value: FormDataEntryValue | FormDataEntryValue[] | undefined,
    values: FormValues,
    context: Context,
  ) => string | null;
};

export type FormRule<Context = unknown> = {
  fields: FormFieldRule<Context>[];
  validate?: (values: FormValues, context: Context) => FormValidationIssue[];
};

export class FormValidationError extends Error {
  issues: FormValidationIssue[];

  /** 保存全部校验问题，供提交入口和界面统一处理。 */
  constructor(issues: FormValidationIssue[]) {
    super(issues[0]?.message || "表单内容有误，请检查后重试");
    this.name = "FormValidationError";
    this.issues = issues;
  }
}

/** 把 FormData 转换成按字段名索引的值对象，并保留同名多值字段。 */
export function formDataValues(formData: FormData): FormValues {
  const values: FormValues = {};
  for (const [name, value] of formData.entries()) {
    const existing = values[name];
    if (existing === undefined) {
      values[name] = value;
    } else if (Array.isArray(existing)) {
      existing.push(value);
    } else {
      values[name] = [existing, value];
    }
  }
  return values;
}

/** 判断字段值是否为空；空文件、空字符串和空数组都视为空值。 */
export function isEmptyFormValue(value: FormDataEntryValue | FormDataEntryValue[] | undefined): boolean {
  if (value === undefined) return true;
  if (Array.isArray(value)) return value.length === 0 || value.every((item) => isEmptyFormValue(item));
  if (value instanceof File) return value.size === 0;
  return value.trim() === "";
}

/** 执行纯数据表单校验，返回全部字段和跨字段问题。 */
export function validateFormData<Context>(
  formData: FormData,
  rule: FormRule<Context>,
  context: Context,
): FormValidationIssue[] {
  const values = formDataValues(formData);
  const issues: FormValidationIssue[] = [];
  for (const fieldRule of rule.fields) {
    const value = values[fieldRule.name];
    const required = typeof fieldRule.required === "function"
      ? fieldRule.required(values, context)
      : Boolean(fieldRule.required);
    if (required && isEmptyFormValue(value)) {
      issues.push({ field: fieldRule.name, message: `${fieldRule.label}为必填项` });
      continue;
    }
    if (!isEmptyFormValue(value) && fieldRule.validate) {
      const message = fieldRule.validate(value, values, context);
      if (message) issues.push({ field: fieldRule.name, message });
    }
  }
  if (rule.validate) issues.push(...rule.validate(values, context));
  return issues;
}

/** 清除表单控件上一次留下的自定义错误状态。 */
export function clearFormValidation(form: HTMLFormElement): void {
  for (const control of Array.from(form.elements)) {
    if (isValidatableControl(control)) {
      control.setCustomValidity("");
      control.removeAttribute("aria-invalid");
    }
  }
}

/** 校验 HTML 表单，失败时标记并聚焦首个错误字段。 */
export function validateForm<Context = undefined>(
  form: HTMLFormElement,
  rule: FormRule<Context>,
  context: Context = undefined as Context,
): FormData {
  clearFormValidation(form);
  const formData = new FormData(form);
  const issues = validateFormData(formData, rule, context);
  if (issues.length === 0) return formData;

  for (const issue of issues) {
    if (!issue.field) continue;
    const control = namedFormControl(form, issue.field);
    if (!control) continue;
    control.setCustomValidity(issue.message);
    control.setAttribute("aria-invalid", "true");
    registerValidationClear(control);
  }
  const firstField = issues.find((issue) => issue.field)?.field;
  const firstControl = firstField ? namedFormControl(form, firstField) : null;
  firstControl?.focus();
  form.reportValidity();
  throw new FormValidationError(issues);
}

/** 查找指定名称下第一个可校验的表单控件。 */
function namedFormControl(form: HTMLFormElement, name: string): HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement | null {
  const item = form.elements.namedItem(name);
  if (isValidatableControl(item)) return item;
  if (item instanceof RadioNodeList) {
    for (const entry of Array.from(item)) {
      if (isValidatableControl(entry)) return entry;
    }
  }
  return null;
}

/** 判断元素是否支持浏览器原生表单校验接口。 */
function isValidatableControl(value: unknown): value is HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement {
  return value instanceof HTMLInputElement || value instanceof HTMLSelectElement || value instanceof HTMLTextAreaElement;
}

/** 用户修改错误字段后立即清除旧提示，下一次提交会重新执行完整规则。 */
function registerValidationClear(control: HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement): void {
  const clear = () => {
    control.setCustomValidity("");
    control.removeAttribute("aria-invalid");
  };
  control.addEventListener("input", clear, { once: true });
  control.addEventListener("change", clear, { once: true });
}
