import { useState } from 'react';
import {
  Container,
  Form,
  Button,
  InputGroup,
  Card,
  Row,
  Col,
} from 'react-bootstrap';
import { Link, useNavigate } from 'react-router-dom';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
  faEye,
  faEyeSlash,
  faUser,
  faEnvelope,
  faLock,
  faUserPlus,
} from '@fortawesome/free-solid-svg-icons';
import { toast } from 'react-toastify';
import { useAuth } from '../contexts/AuthContext';
import PasswordInput from '../components/PasswordInput';

const Register = () => {
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    password: '',
  });
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [errors, setErrors] = useState({
    name: '',
    password: [],
  });
  const { register } = useAuth();
  const navigate = useNavigate();

  // 驗證姓名
  const validateName = (name) => {
    if (name.length < 3 || name.length > 20) {
      return '姓名長度必須在3-20個字元之間';
    }
    if (!/^[\u4e00-\u9fa5a-zA-Z0-9]+$/.test(name)) {
      return '姓名不能包含特殊字元';
    }
    return '';
  };

  // 驗證密碼
  const validatePassword = (password, name, email) => {
    const errors = [];

    // 檢查密碼長度
    if (password.length < 8) {
      errors.push('密碼必須至少包含8個字元');
    }

    // 檢查是否全是數字
    if (/^\d+$/.test(password)) {
      errors.push('密碼不能完全是數字');
    }

    // 檢查是否與個人資訊相似
    if (name && password.toLowerCase().includes(name.toLowerCase())) {
      errors.push('密碼不能與姓名相似');
    }
    if (
      email &&
      password.toLowerCase().includes(email.split('@')[0].toLowerCase())
    ) {
      errors.push('密碼不能與電子郵件相似');
    }

    // 檢查是否為常見密碼
    const commonPasswords = ['password', '12345678', 'qwerty', 'admin123'];
    if (commonPasswords.includes(password.toLowerCase())) {
      errors.push('密碼不能是常見的密碼');
    }

    return errors;
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));

    // 即時驗證
    if (name === 'name') {
      setErrors((prev) => ({
        ...prev,
        name: validateName(value),
      }));
    } else if (name === 'password') {
      setErrors((prev) => ({
        ...prev,
        password: validatePassword(value, formData.name, formData.email),
      }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    // 提交前再次驗證
    const nameError = validateName(formData.name);
    const passwordErrors = validatePassword(
      formData.password,
      formData.name,
      formData.email,
    );

    if (nameError || passwordErrors.length > 0) {
      setErrors({
        name: nameError,
        password: passwordErrors,
      });
      return;
    }

    setIsLoading(true);
    try {
      await register(formData.name, formData.email, formData.password);
      toast.success('註冊成功');
      navigate('/');
    } catch (err) {
      console.error('註冊錯誤:', err);
      toast.error(err.message || '註冊失敗');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Container>
      <Row className="justify-content-center">
        <Col xs={12} sm={10} md={8} lg={6} xl={5}>
          <Card className="shadow-sm">
            <Card.Body className="p-4">
              <div className="text-center mb-4">
                <h2 className="mb-0">註冊</h2>
                <p className="text-muted">建立您的帳號</p>
              </div>
              <Form onSubmit={handleSubmit}>
                <Form.Group className="mb-3">
                  <Form.Label>
                    <FontAwesomeIcon icon={faUser} className="me-2" />
                    姓名
                  </Form.Label>
                  <Form.Control
                    type="text"
                    name="name"
                    value={formData.name}
                    onChange={handleChange}
                    required
                    placeholder="請輸入姓名"
                    isInvalid={!!errors.name}
                  />
                  {errors.name && (
                    <Form.Text className="text-danger fw-bold">
                      {errors.name}
                    </Form.Text>
                  )}
                </Form.Group>

                <Form.Group className="mb-3">
                  <Form.Label>
                    <FontAwesomeIcon icon={faEnvelope} className="me-2" />
                    電子郵件
                  </Form.Label>
                  <Form.Control
                    type="email"
                    name="email"
                    value={formData.email}
                    onChange={handleChange}
                    required
                    placeholder="請輸入電子郵件"
                  />
                </Form.Group>

                <PasswordInput
                  value={formData.password}
                  onChange={handleChange}
                  errors={errors.password}
                />

                <div className="d-grid gap-2">
                  <Button
                    type="submit"
                    variant="primary"
                    disabled={isLoading}
                    className="py-2"
                  >
                    <FontAwesomeIcon icon={faUserPlus} className="me-2" />
                    {isLoading ? '註冊中...' : '註冊'}
                  </Button>
                </div>

                <div className="text-center mt-3">
                  <span>已有帳號？</span>
                  <Link to="/login" className="text-decoration-none ms-2">
                    登入
                  </Link>
                </div>
              </Form>
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
};

export default Register;
