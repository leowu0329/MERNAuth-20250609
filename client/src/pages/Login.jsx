import { useState } from 'react';
import { Form, Button, Card, Container, Row, Col } from 'react-bootstrap';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { toast } from 'react-toastify';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
  faUser,
  faEnvelope,
  faSignInAlt,
} from '@fortawesome/free-solid-svg-icons';
import PasswordInput from '../components/PasswordInput';

const Login = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: '',
  });
  const [isLoading, setIsLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      await login(formData.email, formData.password);
      toast.success('登入成功');
      navigate('/');
    } catch (err) {
      toast.error(err.response?.data?.message || '登入失敗');
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
                <h2 className="mb-0">登入</h2>
                <p className="text-muted">歡迎回來！請登入您的帳號</p>
              </div>
              <Form onSubmit={handleSubmit}>
                <Form.Group className="mb-3">
                  <Form.Label>
                    <FontAwesomeIcon icon={faUser} className="me-2" />
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
                />

                <div className="d-grid gap-2">
                  <Button
                    type="submit"
                    variant="primary"
                    disabled={isLoading}
                    className="py-2"
                  >
                    <FontAwesomeIcon icon={faSignInAlt} className="me-2" />
                    {isLoading ? '登入中...' : '登入'}
                  </Button>
                </div>

                <div className="text-center mt-3">
                  <Link to="/forgot-password" className="text-decoration-none">
                    忘記密碼？
                  </Link>
                  <span className="mx-2">|</span>
                  <Link to="/register" className="text-decoration-none">
                    註冊新帳號
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

export default Login;
