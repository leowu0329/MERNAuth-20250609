import { Container, Card, Row, Col } from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
  faUserShield,
  faLock,
  faEnvelope,
} from '@fortawesome/free-solid-svg-icons';

const Home = () => {
  return (
    <Container className="mt-5">
      <div className="text-center mb-5">
        <h1 className="display-4 fw-bold text-primary">
          歡迎使用 MERN 登入系統
        </h1>
        <p className="lead text-muted">
          這是一個使用 MERN + Vite 建立的完整使用者登入系統
        </p>
      </div>

      <Row className="g-4">
        <Col md={4}>
          <Card className="h-100 shadow-sm hover-shadow">
            <Card.Body className="text-center p-4">
              <FontAwesomeIcon
                icon={faUserShield}
                className="text-primary fa-3x mb-3"
              />
              <Card.Title className="h4">安全可靠</Card.Title>
              <Card.Text className="text-muted">
                使用 JWT 令牌驗證，確保您的帳號安全
              </Card.Text>
            </Card.Body>
          </Card>
        </Col>
        <Col md={4}>
          <Card className="h-100 shadow-sm hover-shadow">
            <Card.Body className="text-center p-4">
              <FontAwesomeIcon
                icon={faLock}
                className="text-primary fa-3x mb-3"
              />
              <Card.Title className="h4">密碼保護</Card.Title>
              <Card.Text className="text-muted">
                密碼加密儲存，支援密碼重設功能
              </Card.Text>
            </Card.Body>
          </Card>
        </Col>
        <Col md={4}>
          <Card className="h-100 shadow-sm hover-shadow">
            <Card.Body className="text-center p-4">
              <FontAwesomeIcon
                icon={faEnvelope}
                className="text-primary fa-3x mb-3"
              />
              <Card.Title className="h4">郵件通知</Card.Title>
              <Card.Text className="text-muted">
                忘記密碼時，自動發送重設連結
              </Card.Text>
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
};

export default Home;
