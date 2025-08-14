# كاسر كلمات المرور (Password Cracker)

## الوصف
أداة لكسر كلمات المرور المشفرة باستخدام هجمات القوة الغاشمة (Brute-force) وهجمات القاموس (Dictionary Attack).

## الميزات
- دعم خوارزميات التشفير الشائعة (MD5, SHA1, SHA256, SHA512)
- هجوم القوة الغاشمة مع تحديد مجموعة الأحرف وطول كلمة المرور
- هجوم القاموس باستخدام ملف قاموس مخصص
- تسجيل كافة الأحداث في ملف log

## المتطلبات
- Python 3.6+
- نظام تشغيل Windows/Linux

## طريقة الاستخدام
```bash
python main.py crack --hash <كلمة المرور المشفرة> --type <نوع التشفير> --bruteforce --charset <مجموعة الأحرف> --max-length <أقصى طول>
python main.py crack --hash <كلمة المرور المشفرة> --type <نوع التشفير> --dictionary <مسار ملف القاموس>
```

## الأمثلة
```bash
# كسر كلمة مرور مشفرة بـ SHA256 باستخدام القوة الغاشمة
python main.py crack --hash 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8 --type sha256 --bruteforce --charset lower --max-length 4

# كسر كلمة مرور مشفرة بـ MD5 باستخدام قاموس
python main.py crack --hash 0cc175b9c0f1b6a831c399e269772661 --type md5 --dictionary common_passwords.txt
```

## معالجة الأخطاء
- يتعامل مع أنواع التشفير غير المدعومة
- يسجل أخطاء قراءة ملف القاموس
- يوفر رسائل واضحة عند عدم العثور على كلمة المرور

## الترخيص
هذا المشروع مرخص تحت رخصة MIT.


