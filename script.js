/**
 * ═══════════════════════════════════════════════════════════════════
 * دليلك الطبي - نظام إدارة واجهة المستخدم المؤمّن v3.0
 * تطوير: Senior Full-Stack Developer
 * 
 * ملاحظات أمنية:
 * - استخدام Strict Mode لمنع الأخطاء الشائعة
 * - تنظيف جميع المدخلات من XSS و HTML Injection
 * - استخدام textContent بدلاً من innerHTML عند الإمكان
 * - التحقق من صحة البيانات قبل التخزين
 * ═══════════════════════════════════════════════════════════════════
 */

'use strict';

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 1. وظائف الحماية الأمنية (Security Functions)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/**
 * تنظيف النصوص من XSS و HTML Injection
 * يزيل جميع علامات HTML والسكريبتات الخطرة
 */
const sanitizeInput = (input) => {
    if (typeof input !== 'string') return '';
    
    // إنشاء عنصر مؤقت لتنظيف HTML
    const temp = document.createElement('div');
    temp.textContent = input;
    let cleaned = temp.innerHTML;
    
    // إزالة المحارف الخطرة
    cleaned = cleaned
        .replace(/[<>]/g, '') // إزالة < و >
        .replace(/javascript:/gi, '') // إزالة javascript:
        .replace(/on\w+\s*=/gi, '') // إزالة event handlers
        .replace(/eval\(/gi, '') // إزالة eval
        .replace(/<script/gi, '') // إزالة script tags
        .replace(/<iframe/gi, ''); // إزالة iframe tags
    
    return cleaned.trim();
};

/**
 * التحقق من صحة النص
 * يضمن أن النص ضمن الحدود المقبولة
 */
const validateText = (text, minLength = 1, maxLength = 200) => {
    if (!text || typeof text !== 'string') return false;
    const cleaned = sanitizeInput(text);
    return cleaned.length >= minLength && cleaned.length <= maxLength;
};

/**
 * إنشاء عنصر HTML آمن
 */
const createSafeElement = (tag, textContent = '', className = '') => {
    const element = document.createElement(tag);
    if (textContent) element.textContent = textContent;
    if (className) element.className = className;
    return element;
};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 2. قاعدة بيانات الأطباء (Database)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const doctorsData = [
    {
        id: 101,
        name: "د. أحمد حسين مرزه",
        spec: "الباطنية والقلبية",
        phone: "9647869000712",
        img: "https://i.ibb.co/V0qvvKSR/image.png",
        city: "النجف",
        keywords: ["قلب", "قلبية", "باطنية", "ضغط", "سكري"]
    },
    {
        id: 102,
        name: "د. حسنين الشيباني",
        spec: "طب وجراحة العيون",
        phone: "9647749496210",
        img: "https://i.ibb.co/Lznq55Pn/image.png",
        city: "النجف",
        keywords: ["عيون", "نظر", "شبكية", "قرنية", "عدسات"]
    },
    {
        id: 103,
        name: "د. نوار جمعة الماجدي",
        spec: "المفاصل والكسور",
        phone: "9647813031024",
        img: "https://i.ibb.co/4nGrzkQr/image.png",
        city: "النجف",
        keywords: ["عظام", "كسور", "مفاصل", "عمود فقري"]
    },
    {
        id: 104,
        name: "د. إحسان تويج",
        spec: "جراحة العظام والكسور",
        phone: "9647813031024",
        img: "https://i.ibb.co/d0ByW2zs/image.png",
        city: "النجف",
        keywords: ["جراحة", "عظام", "كسور", "عمليات"]
    },
    {
        id: 105,
        name: "د. مقداد الرضوي",
        spec: "جراحة الكلى والمسالك",
        phone: "9647869000712",
        img: "https://i.ibb.co/tMf2tvkz/image.png",
        city: "النجف",
        keywords: ["كلى", "مسالك", "بولية", "حصوات"]
    }
];

// المحافظات التي تحتوي على بيانات
const availableCities = ["النجف"];

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 3. عناصر DOM
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const elements = {
    splashScreen: document.getElementById('splashScreen'),
    citySelect: document.getElementById('citySelect'),
    searchInput: document.getElementById('searchInput'),
    clearSearch: document.getElementById('clearSearch'),
    doctorsGrid: document.getElementById('doctorsGrid'),
    listTitle: document.getElementById('listTitle'),
    noResults: document.getElementById('noResults'),
    comingSoonMessage: document.getElementById('comingSoonMessage'),
    selectedProvince: document.getElementById('selectedProvince'),
    totalDoctors: document.getElementById('totalDoctors'),
    totalReviews: document.getElementById('totalReviews'),
    aboutModal: document.getElementById('aboutModal'),
    helpModal: document.getElementById('helpModal'),
    aboutTrigger: document.getElementById('aboutTrigger'),
    helpTrigger: document.getElementById('helpTrigger'),
    mainNav: document.getElementById('mainNav'),
    scrollToTop: document.getElementById('scrollToTop'),
    filterButtons: document.querySelectorAll('.filter-btn')
};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 4. المتغيرات والحالة (State)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

let currentFilter = 'all';
let searchTerm = '';
let selectedCity = 'النجف';

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 5. وظائف مساعدة (Utilities)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/**
 * تنظيف النصوص للبحث الذكي
 */
const normalizeText = (text) => {
    if (!text) return '';
    return text
        .replace(/[أإآ]/g, 'ا')
        .replace(/ة/g, 'ه')
        .replace(/ى/g, 'ي')
        .replace(/[\u064B-\u0652]/g, '')
        .toLowerCase()
        .trim();
};

/**
 * جلب التقييمات من LocalStorage (مع تنظيف)
 */
const getReviews = (doctorId) => {
    try {
        const stored = localStorage.getItem(`reviews_${doctorId}`);
        if (!stored) return [];
        
        const reviews = JSON.parse(stored);
        // التحقق من أن البيانات صحيحة
        if (!Array.isArray(reviews)) return [];
        
        // تنظيف كل تقييم
        return reviews.filter(review => {
            return review && 
                   typeof review.text === 'string' && 
                   review.text.length > 0 &&
                   review.date;
        });
    } catch (error) {
        console.error('Error reading reviews:', error);
        return [];
    }
};

/**
 * حفظ تقييم جديد (مع تنظيف XSS)
 */
const saveReview = (doctorId, reviewText) => {
    // تنظيف النص
    const cleanText = sanitizeInput(reviewText);
    
    // التحقق من الصحة
    if (!validateText(cleanText, 5, 200)) {
        return false;
    }
    
    try {
        const reviews = getReviews(doctorId);
        
        // إضافة التقييم الجديد
        reviews.push({
            text: cleanText,
            date: new Date().toISOString(),
            id: Date.now()
        });
        
        // حفظ في LocalStorage
        localStorage.setItem(`reviews_${doctorId}`, JSON.stringify(reviews));
        return true;
    } catch (error) {
        console.error('Error saving review:', error);
        return false;
    }
};

/**
 * حساب إجمالي التقييمات
 */
const getTotalReviews = () => {
    let total = 0;
    doctorsData.forEach(doctor => {
        const reviews = getReviews(doctor.id);
        total += reviews.length;
    });
    return total;
};

/**
 * تحديث عداد التقييمات
 */
const updateReviewsCounter = () => {
    const total = getTotalReviews();
    if (elements.totalReviews) {
        elements.totalReviews.textContent = total;
    }
};

/**
 * عرض إشعار
 */
const showNotification = (message, type = 'info') => {
    const notification = createSafeElement('div', sanitizeInput(message));
    notification.style.cssText = `
        position: fixed; top: 100px; right: 20px;
        background: ${type === 'success' ? '#25D366' : type === 'warning' ? '#ff9800' : '#003366'};
        color: white; padding: 15px 25px; border-radius: 12px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.2); z-index: 9999;
        animation: slideInRight 0.3s ease-out; font-weight: 600;
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'fadeOut 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 6. الفلترة والبحث
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/**
 * فلترة الأطباء
 */
const filterDoctors = () => {
    const city = elements.citySelect.value;
    const term = normalizeText(sanitizeInput(elements.searchInput.value));
    
    selectedCity = city;
    searchTerm = term;
    
    // تحديث العنوان
    elements.listTitle.textContent = `أطباء الثقة في ${city}`;
    
    // التحقق من توفر البيانات في المحافظة
    if (!availableCities.includes(city)) {
        showComingSoonMessage(city);
        return;
    }
    
    // إخفاء رسالة "قريباً"
    elements.comingSoonMessage.style.display = 'none';
    
    // الفلترة
    const filtered = doctorsData.filter(doctor => {
        const cityMatch = doctor.city === city;
        
        let searchMatch = true;
        if (term) {
            const normalizedName = normalizeText(doctor.name);
            const normalizedSpec = normalizeText(doctor.spec);
            const keywordsMatch = doctor.keywords.some(keyword => 
                normalizeText(keyword).includes(term)
            );
            
            searchMatch = normalizedName.includes(term) || 
                         normalizedSpec.includes(term) ||
                         keywordsMatch;
        }
        
        let specMatch = true;
        if (currentFilter !== 'all') {
            const normalizedSpec = normalizeText(doctor.spec);
            const normalizedFilter = normalizeText(currentFilter);
            specMatch = normalizedSpec.includes(normalizedFilter);
        }
        
        return cityMatch && searchMatch && specMatch;
    });
    
    renderDoctors(filtered);
};

/**
 * عرض رسالة "قريباً" للمحافظات غير المتوفرة
 */
const showComingSoonMessage = (city) => {
    elements.doctorsGrid.style.display = 'none';
    elements.noResults.style.display = 'none';
    elements.comingSoonMessage.style.display = 'block';
    elements.selectedProvince.textContent = sanitizeInput(city);
};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 7. عرض الأطباء
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

/**
 * رسم بطاقات الأطباء (محمي من XSS)
 */
const renderDoctors = (doctors) => {
    // تحديث العداد
    if (elements.totalDoctors) {
        elements.totalDoctors.textContent = doctors.length;
    }
    
    // إفراغ الشبكة
    elements.doctorsGrid.innerHTML = '';
    
    // إخفاء رسالة "قريباً"
    elements.comingSoonMessage.style.display = 'none';
    
    // عرض رسالة عدم وجود نتائج
    if (doctors.length === 0) {
        elements.noResults.style.display = 'block';
        elements.doctorsGrid.style.display = 'none';
        return;
    } else {
        elements.noResults.style.display = 'none';
        elements.doctorsGrid.style.display = 'grid';
    }
    
    // رسم البطاقات
    doctors.forEach((doctor, index) => {
        const card = createDoctorCard(doctor, index);
        elements.doctorsGrid.appendChild(card);
    });
};

/**
 * إنشاء بطاقة طبيب (محمي من XSS)
 */
const createDoctorCard = (doctor, index) => {
    const card = document.createElement('div');
    card.className = 'doctor-card';
    card.style.animationDelay = `${index * 0.1}s`;
    
    // جلب التقييمات
    const reviews = getReviews(doctor.id);
    
    // إنشاء عناصر البطاقة بشكل آمن
    const img = document.createElement('img');
    img.src = doctor.img;
    img.className = 'doc-img';
    img.alt = sanitizeInput(doctor.name);
    img.loading = 'lazy';
    img.onerror = function() {
        this.src = 'https://via.placeholder.com/140?text=صورة+غير+متوفرة';
    };
    
    const nameElement = createSafeElement('h2', doctor.name);
    const specElement = createSafeElement('p', doctor.spec);
    
    const whatsappBtn = document.createElement('a');
    whatsappBtn.href = `https://wa.me/${doctor.phone}`;
    whatsappBtn.className = 'btn-whatsapp';
    whatsappBtn.target = '_blank';
    whatsappBtn.rel = 'noopener noreferrer';
    whatsappBtn.textContent = '📱 حجز موعد عبر واتساب';
    
    // قسم التقييمات
    const reviewsSection = document.createElement('div');
    reviewsSection.className = 'reviews-section';
    
    const reviewsTitle = createSafeElement('h3', `💬 التقييمات (${reviews.length})`);
    reviewsTitle.style.cssText = 'color: var(--primary-color); margin-bottom: 15px; font-size: 1.2rem;';
    
    const revList = document.createElement('div');
    revList.className = 'rev-list';
    
    if (reviews.length > 0) {
        reviews.forEach(review => {
            const reviewItem = document.createElement('div');
            reviewItem.className = 'review-item';
            
            const dateEl = createSafeElement('div', new Date(review.date).toLocaleDateString('ar-IQ'));
            dateEl.className = 'review-date';
            
            const textEl = createSafeElement('div', review.text);
            
            reviewItem.appendChild(dateEl);
            reviewItem.appendChild(textEl);
            revList.appendChild(reviewItem);
        });
    } else {
        const emptyMsg = createSafeElement('div', 'لا توجد تقييمات بعد. كن أول من يضيف تقييماً!');
        emptyMsg.style.cssText = 'text-align: center; padding: 20px; color: #888;';
        revList.appendChild(emptyMsg);
    }
    
    // حقل إضافة تقييم
    const revInputArea = document.createElement('div');
    revInputArea.className = 'rev-input-area';
    
    const input = document.createElement('input');
    input.type = 'text';
    input.id = `review-input-${doctor.id}`;
    input.placeholder = 'شارك تجربتك مع الطبيب...';
    input.maxLength = 200;
    
    const submitBtn = document.createElement('button');
    submitBtn.textContent = 'نشر';
    submitBtn.onclick = () => handleReviewSubmit(doctor.id);
    
    revInputArea.appendChild(input);
    revInputArea.appendChild(submitBtn);
    
    reviewsSection.appendChild(reviewsTitle);
    reviewsSection.appendChild(revList);
    reviewsSection.appendChild(revInputArea);
    
    // تجميع البطاقة
    card.appendChild(img);
    card.appendChild(nameElement);
    card.appendChild(specElement);
    card.appendChild(whatsappBtn);
    card.appendChild(reviewsSection);
    
    return card;
};

/**
 * معالجة إرسال تقييم (محمي من XSS)
 */
const handleReviewSubmit = (doctorId) => {
    const input = document.getElementById(`review-input-${doctorId}`);
    if (!input) return;
    
    const reviewText = input.value.trim();
    
    // التحقق من الصحة
    if (!reviewText) {
        showNotification('⚠️ الرجاء كتابة تقييمك أولاً', 'warning');
        return;
    }
    
    if (!validateText(reviewText, 5, 200)) {
        showNotification('⚠️ التقييم قصير جداً أو يحتوي على محارف غير مسموحة', 'warning');
        return;
    }
    
    // حفظ التقييم
    const success = saveReview(doctorId, reviewText);
    
    if (success) {
        input.value = '';
        showNotification('✅ تم إضافة تقييمك بنجاح!', 'success');
        updateReviewsCounter();
        filterDoctors(); // إعادة رسم البطاقات
    } else {
        showNotification('❌ حدث خطأ. حاول مرة أخرى', 'warning');
    }
};

// تصدير الدالة للاستخدام العام
window.handleReviewSubmit = handleReviewSubmit;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 8. المودال
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

window.toggleAbout = () => {
    elements.aboutModal.classList.toggle('active');
    document.body.style.overflow = elements.aboutModal.classList.contains('active') ? 'hidden' : '';
};

window.toggleHelp = () => {
    elements.helpModal.classList.toggle('active');
    document.body.style.overflow = elements.helpModal.classList.contains('active') ? 'hidden' : '';
};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 9. التنقل والتمرير
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const handleScroll = () => {
    const scrolled = window.scrollY > 50;
    
    if (scrolled) {
        elements.mainNav.classList.add('scrolled');
    } else {
        elements.mainNav.classList.remove('scrolled');
    }
    
    if (window.scrollY > 300) {
        elements.scrollToTop.classList.add('visible');
    } else {
        elements.scrollToTop.classList.remove('visible');
    }
};

elements.scrollToTop?.addEventListener('click', () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 10. الفلاتر السريعة
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

elements.filterButtons.forEach(button => {
    button.addEventListener('click', () => {
        elements.filterButtons.forEach(btn => btn.classList.remove('active'));
        button.classList.add('active');
        currentFilter = button.dataset.filter;
        filterDoctors();
    });
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 11. مستمعات الأحداث
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

elements.citySelect.addEventListener('change', filterDoctors);

elements.searchInput.addEventListener('input', (e) => {
    if (e.target.value) {
        elements.clearSearch.style.display = 'flex';
    } else {
        elements.clearSearch.style.display = 'none';
    }
    filterDoctors();
});

elements.clearSearch?.addEventListener('click', () => {
    elements.searchInput.value = '';
    elements.clearSearch.style.display = 'none';
    filterDoctors();
});

window.addEventListener('scroll', handleScroll);

elements.aboutTrigger?.addEventListener('click', window.toggleAbout);
elements.helpTrigger?.addEventListener('click', window.toggleHelp);

document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
        if (elements.aboutModal.classList.contains('active')) {
            window.toggleAbout();
        }
        if (elements.helpModal.classList.contains('active')) {
            window.toggleHelp();
        }
    }
});

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// 12. التهيئة
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

const initializeApp = () => {
    // إخفاء شاشة الترحيب
    setTimeout(() => {
        elements.splashScreen.style.opacity = '0';
        setTimeout(() => {
            elements.splashScreen.style.display = 'none';
        }, 800);
    }, 2000);
    
    // عرض الأطباء الأولي
    renderDoctors(doctorsData);
    
    // تحديث عداد التقييمات
    updateReviewsCounter();
    
    console.log('%c🏥 دليلك الطبي v3.0 - نسخة محمية', 'color: #003366; font-size: 20px; font-weight: bold;');
    console.log('%c✅ النظام محمي من XSS و HTML Injection', 'color: #25D366; font-size: 14px;');
    console.log(`📊 عدد الأطباء: ${doctorsData.length}`);
    console.log(`💬 عدد التقييمات: ${getTotalReviews()}`);
    console.log(`🇮🇶 محافظات متوفرة: ${availableCities.join(', ')}`);
};

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// بدء التطبيق
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeApp);
} else {
    initializeApp();
}

// أنيميشنات CSS إضافية
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from { transform: translateX(-100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes fadeOut {
        to { opacity: 0; transform: translateX(-20px); }
    }
`;
document.head.appendChild(style);

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
// نهاية الملف - جميع الوظائف محمية من XSS
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━