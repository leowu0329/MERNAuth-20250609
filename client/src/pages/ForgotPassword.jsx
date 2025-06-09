import { useState } from 'react';
import { Container, Form, Button, Card } from 'react-bootstrap';
import { Link } from 'react-router-dom';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { faEnvelope, faArrowLeft } from '@fortawesome/free-solid-svg-icons';
import { toast } from 'react-toastify';
import axios from 'axios';

const ForgotPassword = () => {
  const [email, setEmail] = useState('');
  const [isLoading, setIsLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      const res = await axios.post(
        'http://localhost:5000/api/auth/forgot-password',
        { email },
      );

      toast.success(res.data.message);
    } catch (err) {
      toast.error(err.response?.data?.message || '發送失敗');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <Container className="mt-5">
      <div className="row justify-content-center">
        <div className="col-md-6 col-lg-5">
          <Card className="shadow-sm">
            <Card.Body className="p-5">
              <h2 className="text-center mb-4">忘記密碼</h2>
              <p className="text-muted text-center mb-4">
                請輸入您的註冊信箱，我們將會發送重設密碼連結給您
              </p>
              <Form onSubmit={handleSubmit}>
                <Form.Group className="mb-4">
                  <Form.Label>
                    <FontAwesomeIcon icon={faEnvelope} className="me-2" />
                    信箱
                  </Form.Label>
                  <Form.Control
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="請輸入註冊信箱"
                    required
                  />
                </Form.Group>
                <Button
                  type="submit"
                  variant="primary"
                  className="w-100 mb-3"
                  disabled={isLoading}
                >
                  {isLoading ? '發送中...' : '發送重設連結'}
                </Button>
                <div className="text-center">
                  <Link to="/login" className="text-decoration-none">
                    <FontAwesomeIcon icon={faArrowLeft} className="me-2" />
                    返回登入
                  </Link>
                </div>
              </Form>
            </Card.Body>
          </Card>
        </div>
      </div>
    </Container>
  );
};

export default ForgotPassword;
