import { useState, useEffect } from 'react';
import {
  Container,
  Card,
  Form,
  Button,
  Row,
  Col,
  Tabs,
  Tab,
} from 'react-bootstrap';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import {
  faUser,
  faEnvelope,
  faEdit,
  faSave,
  faTimes,
  faIdCard,
  faCalendar,
  faPhone,
  faMobile,
  faBuilding,
  faClock,
  faUserShield,
  faMap,
} from '@fortawesome/free-solid-svg-icons';
import { toast } from 'react-toastify';
import axios from 'axios';
import { useAuth } from '../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';

const Profile = () => {
  const { user: authUser, updateUser } = useAuth();
  const navigate = useNavigate();
  const [isEditing, setIsEditing] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [formData, setFormData] = useState({
    name: '',
    email: '',
    role: '一般使用者',
    workArea: '',
    identityId: '',
    birthday: '',
    phone: '',
    mobile: '',
    address: {
      city: '',
      district: '',
      village: '',
      neighborhood: '',
      street: '',
      section: '',
      lane: '',
      alley: '',
      number: '',
      floor: '',
    },
    identityType: '',
  });

  useEffect(() => {
    if (authUser) {
      setFormData({
        name: authUser.name || '',
        email: authUser.email || '',
        role: authUser.role || '一般使用者',
        workArea: authUser.workArea || '',
        identityId: authUser.identityId || '',
        birthday: authUser.birthday
          ? new Date(authUser.birthday).toISOString().split('T')[0]
          : '',
        phone: authUser.phone || '',
        mobile: authUser.mobile || '',
        address: {
          city: authUser.address?.city || '',
          district: authUser.address?.district || '',
          village: authUser.address?.village || '',
          neighborhood: authUser.address?.neighborhood || '',
          street: authUser.address?.street || '',
          section: authUser.address?.section || '',
          lane: authUser.address?.lane || '',
          alley: authUser.address?.alley || '',
          number: authUser.address?.number || '',
          floor: authUser.address?.floor || '',
        },
        identityType: authUser.identityType || '',
      });
    }
  }, [authUser]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    if (name.includes('.')) {
      const [parent, child] = name.split('.');
      setFormData((prev) => ({
        ...prev,
        [parent]: {
          ...prev[parent],
          [child]: value,
        },
      }));
    } else {
      setFormData((prev) => ({ ...prev, [name]: value }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      const dataToSend = {
        ...formData,
        address: {
          city: formData.address.city || '',
          district: formData.address.district || '',
          village: formData.address.village || '',
          neighborhood: formData.address.neighborhood || '',
          street: formData.address.street || '',
          section: formData.address.section || '',
          lane: formData.address.lane || '',
          alley: formData.address.alley || '',
          number: formData.address.number || '',
          floor: formData.address.floor || '',
        },
      };

      // 從 localStorage 獲取 token
      const token = localStorage.getItem('token');
      if (!token) {
        toast.error('請重新登入');
        navigate('/login');
        return;
      }

      const res = await axios.put(
        'http://localhost:5000/api/auth/profile',
        dataToSend,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        },
      );

      if (res.data.success) {
        // 更新 AuthContext 中的用戶資料
        updateUser(res.data.user);
        toast.success(res.data.message || '資料更新成功');
        setIsEditing(false);

        // 延遲跳轉，讓用戶看到成功訊息
        setTimeout(() => {
          navigate('/', { replace: true });
        }, 1000);
      }
    } catch (err) {
      if (err.response?.status === 401) {
        toast.error('請重新登入');
        navigate('/login');
      } else {
        toast.error(err.response?.data?.message || '更新資料失敗');
      }
    } finally {
      setIsLoading(false);
    }
  };

  const handleCancel = () => {
    if (authUser) {
      setFormData({
        name: authUser.name || '',
        email: authUser.email || '',
        role: authUser.role || '一般使用者',
        workArea: authUser.workArea || '',
        identityId: authUser.identityId || '',
        birthday: authUser.birthday
          ? new Date(authUser.birthday).toISOString().split('T')[0]
          : '',
        phone: authUser.phone || '',
        mobile: authUser.mobile || '',
        address: {
          city: authUser.address?.city || '',
          district: authUser.address?.district || '',
          village: authUser.address?.village || '',
          neighborhood: authUser.address?.neighborhood || '',
          street: authUser.address?.street || '',
          section: authUser.address?.section || '',
          lane: authUser.address?.lane || '',
          alley: authUser.address?.alley || '',
          number: authUser.address?.number || '',
          floor: authUser.address?.floor || '',
        },
        identityType: authUser.identityType || '',
      });
    }
    setIsEditing(false);
  };

  return (
    <Container className="mt-5 mb-5">
      <Row className="justify-content-center">
        <Col md={10} lg={8}>
          <Card className="shadow-sm">
            <Card.Body className="p-4">
              <div className="d-flex justify-content-between align-items-center mb-4">
                <h2 className="mb-0">個人資料</h2>
                {!isEditing && (
                  <Button
                    variant="outline-primary"
                    onClick={() => setIsEditing(true)}
                  >
                    <FontAwesomeIcon icon={faEdit} className="me-2" />
                    編輯資料
                  </Button>
                )}
              </div>

              <Tabs defaultActiveKey="basic" className="mb-4">
                <Tab eventKey="basic" title="基本資料">
                  <Form onSubmit={handleSubmit} className="mt-4">
                    <Row>
                      <Col md={6}>
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
                            disabled={!isEditing}
                            required
                          />
                        </Form.Group>
                      </Col>
                      <Col md={6}>
                        <Form.Group className="mb-3">
                          <Form.Label>
                            <FontAwesomeIcon
                              icon={faEnvelope}
                              className="me-2"
                            />
                            電子郵件
                          </Form.Label>
                          <Form.Control
                            type="email"
                            value={authUser?.email || ''}
                            readOnly
                            disabled
                            className="bg-light"
                          />
                          <Form.Text className="text-danger">
                            電子郵件不可更改
                          </Form.Text>
                        </Form.Group>
                      </Col>
                    </Row>

                    <Row>
                      <Col md={6}>
                        <Form.Group className="mb-3">
                          <Form.Label>
                            <FontAwesomeIcon
                              icon={faUserShield}
                              className="me-2"
                            />
                            權限
                          </Form.Label>
                          <Form.Select
                            name="role"
                            value={formData.role}
                            onChange={handleChange}
                            disabled={!isEditing}
                          >
                            <option value="訪客">訪客</option>
                            <option value="一般使用者">一般使用者</option>
                            <option value="管理者">管理者</option>
                          </Form.Select>
                        </Form.Group>
                      </Col>
                      <Col md={6}>
                        <Form.Group className="mb-3">
                          <Form.Label>
                            <FontAwesomeIcon icon={faMap} className="me-2" />
                            工作轄區
                          </Form.Label>
                          <Form.Select
                            name="workArea"
                            value={formData.workArea}
                            onChange={handleChange}
                            disabled={!isEditing}
                          >
                            <option value="">請選擇</option>
                            <option value="雙北桃竹苗">雙北桃竹苗</option>
                            <option value="中彰投">中彰投</option>
                            <option value="雲嘉南">雲嘉南</option>
                            <option value="高高屏">高高屏</option>
                          </Form.Select>
                        </Form.Group>
                      </Col>
                    </Row>

                    <Row>
                      <Col md={6}>
                        <Form.Group className="mb-3">
                          <Form.Label>
                            <FontAwesomeIcon icon={faIdCard} className="me-2" />
                            身分ID
                          </Form.Label>
                          <Form.Control
                            type="text"
                            name="identityId"
                            value={formData.identityId}
                            onChange={handleChange}
                            disabled={!isEditing}
                          />
                        </Form.Group>
                      </Col>
                      <Col md={6}>
                        <Form.Group className="mb-3">
                          <Form.Label>
                            <FontAwesomeIcon
                              icon={faCalendar}
                              className="me-2"
                            />
                            生日
                          </Form.Label>
                          <Form.Control
                            type="date"
                            name="birthday"
                            value={formData.birthday}
                            onChange={handleChange}
                            disabled={!isEditing}
                          />
                        </Form.Group>
                      </Col>
                    </Row>

                    <Row>
                      <Col md={6}>
                        <Form.Group className="mb-3">
                          <Form.Label>
                            <FontAwesomeIcon icon={faPhone} className="me-2" />
                            市話
                          </Form.Label>
                          <Form.Control
                            type="tel"
                            name="phone"
                            value={formData.phone}
                            onChange={handleChange}
                            disabled={!isEditing}
                          />
                        </Form.Group>
                      </Col>
                      <Col md={6}>
                        <Form.Group className="mb-3">
                          <Form.Label>
                            <FontAwesomeIcon icon={faMobile} className="me-2" />
                            手機
                          </Form.Label>
                          <Form.Control
                            type="tel"
                            name="mobile"
                            value={formData.mobile}
                            onChange={handleChange}
                            disabled={!isEditing}
                          />
                        </Form.Group>
                      </Col>
                    </Row>

                    <Row>
                      <Col md={6}>
                        <Form.Group className="mb-3">
                          <Form.Label>
                            <FontAwesomeIcon
                              icon={faBuilding}
                              className="me-2"
                            />
                            身分別
                          </Form.Label>
                          <Form.Select
                            name="identityType"
                            value={formData.identityType}
                            onChange={handleChange}
                            disabled={!isEditing}
                          >
                            <option value="">請選擇</option>
                            <option value="公">公</option>
                            <option value="私">私</option>
                          </Form.Select>
                        </Form.Group>
                      </Col>
                    </Row>
                  </Form>
                </Tab>

                <Tab eventKey="address" title="地址資料">
                  <Form onSubmit={handleSubmit} className="mt-4">
                    <Row>
                      <Col md={6}>
                        <Form.Group className="mb-3">
                          <Form.Label>縣市</Form.Label>
                          <Form.Control
                            type="text"
                            name="address.city"
                            value={formData.address.city}
                            onChange={handleChange}
                            disabled={!isEditing}
                          />
                        </Form.Group>
                      </Col>
                      <Col md={6}>
                        <Form.Group className="mb-3">
                          <Form.Label>鄉鎮</Form.Label>
                          <Form.Control
                            type="text"
                            name="address.district"
                            value={formData.address.district}
                            onChange={handleChange}
                            disabled={!isEditing}
                          />
                        </Form.Group>
                      </Col>
                    </Row>

                    <Row>
                      <Col md={6}>
                        <Form.Group className="mb-3">
                          <Form.Label>村里</Form.Label>
                          <Form.Control
                            type="text"
                            name="address.village"
                            value={formData.address.village}
                            onChange={handleChange}
                            disabled={!isEditing}
                          />
                        </Form.Group>
                      </Col>
                      <Col md={6}>
                        <Form.Group className="mb-3">
                          <Form.Label>鄰</Form.Label>
                          <Form.Control
                            type="text"
                            name="address.neighborhood"
                            value={formData.address.neighborhood}
                            onChange={handleChange}
                            disabled={!isEditing}
                          />
                        </Form.Group>
                      </Col>
                    </Row>

                    <Row>
                      <Col md={6}>
                        <Form.Group className="mb-3">
                          <Form.Label>街路</Form.Label>
                          <Form.Control
                            type="text"
                            name="address.street"
                            value={formData.address.street}
                            onChange={handleChange}
                            disabled={!isEditing}
                          />
                        </Form.Group>
                      </Col>
                      <Col md={6}>
                        <Form.Group className="mb-3">
                          <Form.Label>段</Form.Label>
                          <Form.Control
                            type="text"
                            name="address.section"
                            value={formData.address.section}
                            onChange={handleChange}
                            disabled={!isEditing}
                          />
                        </Form.Group>
                      </Col>
                    </Row>

                    <Row>
                      <Col md={6}>
                        <Form.Group className="mb-3">
                          <Form.Label>巷</Form.Label>
                          <Form.Control
                            type="text"
                            name="address.lane"
                            value={formData.address.lane}
                            onChange={handleChange}
                            disabled={!isEditing}
                          />
                        </Form.Group>
                      </Col>
                      <Col md={6}>
                        <Form.Group className="mb-3">
                          <Form.Label>弄</Form.Label>
                          <Form.Control
                            type="text"
                            name="address.alley"
                            value={formData.address.alley}
                            onChange={handleChange}
                            disabled={!isEditing}
                          />
                        </Form.Group>
                      </Col>
                    </Row>

                    <Row>
                      <Col md={6}>
                        <Form.Group className="mb-3">
                          <Form.Label>號</Form.Label>
                          <Form.Control
                            type="text"
                            name="address.number"
                            value={formData.address.number}
                            onChange={handleChange}
                            disabled={!isEditing}
                          />
                        </Form.Group>
                      </Col>
                      <Col md={6}>
                        <Form.Group className="mb-3">
                          <Form.Label>樓</Form.Label>
                          <Form.Control
                            type="text"
                            name="address.floor"
                            value={formData.address.floor}
                            onChange={handleChange}
                            disabled={!isEditing}
                          />
                        </Form.Group>
                      </Col>
                    </Row>
                  </Form>
                </Tab>

                <Tab eventKey="system" title="系統資訊">
                  <div className="mt-4">
                    <Row>
                      <Col md={6}>
                        <div className="mb-3">
                          <h6>
                            <FontAwesomeIcon icon={faClock} className="me-2" />
                            建立時間
                          </h6>
                          <p>
                            {authUser?.createdAt
                              ? new Date(authUser.createdAt).toLocaleString()
                              : '無資料'}
                          </p>
                        </div>
                      </Col>
                      <Col md={6}>
                        <div className="mb-3">
                          <h6>
                            <FontAwesomeIcon icon={faClock} className="me-2" />
                            更新時間
                          </h6>
                          <p>
                            {authUser?.updatedAt
                              ? new Date(authUser.updatedAt).toLocaleString()
                              : '無資料'}
                          </p>
                        </div>
                      </Col>
                    </Row>
                    <Row>
                      <Col md={6}>
                        <div className="mb-3">
                          <h6>
                            <FontAwesomeIcon icon={faClock} className="me-2" />
                            最後登入時間
                          </h6>
                          <p>
                            {authUser?.lastLoginAt
                              ? new Date(authUser.lastLoginAt).toLocaleString(
                                  'zh-TW',
                                  {
                                    year: 'numeric',
                                    month: '2-digit',
                                    day: '2-digit',
                                    hour: '2-digit',
                                    minute: '2-digit',
                                    second: '2-digit',
                                    hour12: false,
                                  },
                                )
                              : '無資料'}
                          </p>
                        </div>
                      </Col>
                    </Row>
                  </div>
                </Tab>
              </Tabs>

              {isEditing && (
                <div className="d-flex gap-2 mt-4">
                  <Button
                    type="submit"
                    variant="primary"
                    className="flex-grow-1"
                    disabled={isLoading}
                    onClick={handleSubmit}
                  >
                    <FontAwesomeIcon icon={faSave} className="me-2" />
                    {isLoading ? '儲存中...' : '儲存變更'}
                  </Button>
                  <Button
                    type="button"
                    variant="outline-secondary"
                    onClick={handleCancel}
                    disabled={isLoading}
                  >
                    <FontAwesomeIcon icon={faTimes} className="me-2" />
                    取消
                  </Button>
                </div>
              )}
            </Card.Body>
          </Card>
        </Col>
      </Row>
    </Container>
  );
};

export default Profile;
