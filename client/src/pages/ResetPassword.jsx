import { useState } from 'react';
import { Form, Button, Card, Container, Row, Col } from 'react-bootstrap';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { toast } from 'react-toastify';
import axios from 'axios';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faKey } from '@fortawesome/free-solid-svg-icons';
import PasswordInput from '../components/PasswordInput';

const ResetPassword = () => {
  const [formData, setFormData] = useState({
    currentPassword: '',
    password: '',
    confirmPassword: '',
  });
  const [isLoading, setIsLoading] = useState(false);
  const [errors, setErrors] = useState({
    password: [],
    confirmPassword: '',
  });
  const { token } = useParams();
  const navigate = useNavigate();

  const validatePassword = (password) => {
    const errors = [];

    if (password.length < 8) {
      errors.push('密碼必須至少包含8個字元');
    }

    if (/^\d+$/.test(password)) {
      errors.push('密碼不能完全是數字');
    }

    return errors;
  };

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));

    if (name === 'password') {
      setErrors((prev) => ({
        ...prev,
        password: validatePassword(value),
        confirmPassword: value !== formData.confirmPassword ? '密碼不一致' : '',
      }));
    } else if (name === 'confirmPassword') {
      setErrors((prev) => ({
        ...prev,
        confirmPassword: value !== formData.password ? '密碼不一致' : '',
      }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    const passwordErrors = validatePassword(formData.password);
    if (
      passwordErrors.length > 0 ||
      formData.password !== formData.confirmPassword
    ) {
      setErrors({
        password: passwordErrors,
        confirmPassword:
          formData.password !== formData.confirmPassword ? '密碼不一致' : '',
      });
      return;
    }

    setIsLoading(true);
    try {
      let response;
      if (token.startsWith('temp-')) {
        // 已登入用戶重設密碼
        response = await axios.put(
          'http://localhost:5000/api/auth/update-password',
          {
            currentPassword: formData.currentPassword,
            newPassword: formData.password,
          },
          {
            headers: {
              Authorization: `Bearer ${localStorage.getItem('token')}`,
            },
          },
        );
      } else {
        // 忘記密碼重設流程
        response = await axios.put(
          `http://localhost:5000/api/auth/reset-password/${token}`,
          {
            password: formData.password,
          },
        );
      }

      // 更新 token
      if (response.data.token) {
        localStorage.setItem('token', response.data.token);
        axios.defaults.headers.common[
          'Authorization'
        ] = `Bearer ${response.data.token}`;
      }

      toast.success('密碼重設成功');
      navigate('/');
    } catch (err) {
      toast.error(err.response?.data?.message || '密碼重設失敗');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Container className="d-flex align-items-center justify-content-center min-vh-100">
      <Row className="w-100 justify-content-center">
        <Col xs={12} sm={10} md={8} lg={6} xl={5}>
          <Card className="shadow-sm">
            <Card.Body className="p-4">
              <div className="text-center mb-4">
                <h2 className="mb-0">重設密碼</h2>
                <p className="text-muted">請輸入您的新密碼</p>
              </div>
              <Form onSubmit={handleSubmit}>
                {token.startsWith('temp-') && (
                  <Form.Group className="mb-3">
                    <PasswordInput
                      value={formData.currentPassword}
                      onChange={handleChange}
                      name="currentPassword"
                      placeholder="請輸入當前密碼"
                      errors={
                        errors.currentPassword ? [errors.currentPassword] : []
                      }
                    />
                  </Form.Group>
                )}

                <Form.Group className="mb-3">
                  <PasswordInput
                    value={formData.password}
                    onChange={handleChange}
                    placeholder="請輸入新密碼"
                    errors={errors.password}
                  />
                </Form.Group>

                <Form.Group className="mb-3">
                  <PasswordInput
                    value={formData.confirmPassword}
                    onChange={handleChange}
                    name="confirmPassword"
                    placeholder="請確認新密碼"
                    errors={
                      errors.confirmPassword ? [errors.confirmPassword] : []
                    }
                  />
                </Form.Group>

                <div className="d-grid gap-2">
                  <Button
                    type="submit"
                    variant="primary"
                    disabled={isLoading}
                    className="py-2"
                  >
                    <FontAwesomeIcon icon={faKey} className="me-2" />
                    {isLoading ? '重設中...' : '重設密碼'}
                  </Button>
                </div>

                <div className="text-center mt-3">
                  <Link to="/login" className="text-decoration-none">
                    返回登入
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

export default ResetPassword;
